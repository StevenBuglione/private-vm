package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type CleanupFunc func(context.Context) error

type cleanupStep struct {
	name string
	fn   CleanupFunc
	done bool
}

type commandKind uint8

const (
	commandTransition commandKind = iota + 1
	commandRegisterCleanup
	commandCleanup
)

type command struct {
	kind          commandKind
	to            Phase
	code          string
	message       string
	workflowState string
	cleanupName   string
	cleanup       CleanupFunc
	response      chan commandResult
}

type commandResult struct {
	snapshot Snapshot
	err      error
}

type entry struct {
	session  *Session
	commands chan command
	done     chan struct{}
	steps    []cleanupStep
}

type Manager struct {
	store       *Store
	maxPerOwner int
	now         func() time.Time
	cleanupWait time.Duration
	mu          sync.RWMutex
	entries     map[string]*entry
	destroyed   map[string]Snapshot
}

func NewManager(store *Store, maxPerOwner int) (*Manager, error) {
	if store == nil {
		return nil, errors.New("session store is required")
	}
	if maxPerOwner < 1 || maxPerOwner > 64 {
		return nil, errors.New("per-owner session quota must be between 1 and 64")
	}
	return &Manager{
		store: store, maxPerOwner: maxPerOwner, now: time.Now, cleanupWait: 30 * time.Second,
		entries: make(map[string]*entry), destroyed: make(map[string]Snapshot),
	}, nil
}

func (m *Manager) Create(ownerUID uint32, role Role) (Snapshot, error) {
	if err := ValidateRole(role); err != nil {
		return Snapshot{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, item := range m.entries {
		if item.session.Snapshot().OwnerUID == ownerUID {
			count++
		}
	}
	if count >= m.maxPerOwner {
		return Snapshot{}, ErrQuotaExceeded
	}
	id, err := randomID()
	if err != nil {
		return Snapshot{}, err
	}
	s, err := NewOwned(id, ownerUID, role, m.now().UTC())
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := s.Snapshot()
	if err := m.store.Create(snapshot); err != nil {
		return Snapshot{}, err
	}
	item := &entry{session: s, commands: make(chan command), done: make(chan struct{})}
	m.entries[id] = item
	go m.run(item)
	return snapshot, nil
}

func (m *Manager) Get(id string, requesterUID uint32) (Snapshot, error) {
	item, err := m.authorizedEntry(id, requesterUID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			if snapshot, ok := m.destroyedSnapshot(id, requesterUID); ok {
				return snapshot, nil
			}
		}
		return Snapshot{}, err
	}
	return item.session.Snapshot(), nil
}

func (m *Manager) List(requesterUID uint32) []Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Snapshot, 0, len(m.entries))
	for _, item := range m.entries {
		snapshot := item.session.Snapshot()
		if requesterUID == 0 || snapshot.OwnerUID == requesterUID {
			result = append(result, snapshot)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result
}

func (m *Manager) Transition(ctx context.Context, id string, requesterUID uint32, to Phase, code, message, workflowState string) (Snapshot, error) {
	return m.send(ctx, id, requesterUID, command{kind: commandTransition, to: to, code: code, message: message, workflowState: workflowState})
}

func (m *Manager) RegisterCleanup(ctx context.Context, id string, requesterUID uint32, name string, cleanup CleanupFunc) error {
	if name == "" || cleanup == nil {
		return errors.New("cleanup step name and function are required")
	}
	_, err := m.send(ctx, id, requesterUID, command{kind: commandRegisterCleanup, cleanupName: name, cleanup: cleanup})
	return err
}

func (m *Manager) Cleanup(ctx context.Context, id string, requesterUID uint32) (Snapshot, error) {
	if snapshot, ok := m.destroyedSnapshot(id, requesterUID); ok {
		return snapshot, nil
	}
	snapshot, err := m.send(ctx, id, requesterUID, command{kind: commandCleanup})
	if err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func (m *Manager) send(ctx context.Context, id string, requesterUID uint32, cmd command) (Snapshot, error) {
	item, err := m.authorizedEntry(id, requesterUID)
	if err != nil {
		return Snapshot{}, err
	}
	cmd.response = make(chan commandResult, 1)
	select {
	case item.commands <- cmd:
	case <-item.done:
		return Snapshot{}, ErrNotFound
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	}
	select {
	case result := <-cmd.response:
		return result.snapshot, result.err
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	}
}

func (m *Manager) authorizedEntry(id string, requesterUID uint32) (*entry, error) {
	m.mu.RLock()
	item := m.entries[id]
	m.mu.RUnlock()
	if item == nil {
		return nil, ErrNotFound
	}
	owner := item.session.Snapshot().OwnerUID
	if requesterUID != 0 && requesterUID != owner {
		return nil, ErrUnauthorized
	}
	return item, nil
}

func (m *Manager) run(item *entry) {
	for cmd := range item.commands {
		switch cmd.kind {
		case commandTransition:
			before := item.session.Snapshot()
			err := item.session.transition(cmd.to, cmd.code, cmd.message, cmd.workflowState, m.now().UTC())
			if err == nil {
				err = m.store.Save(item.session.Snapshot())
				if err != nil {
					item.session.restore(before)
				}
			}
			cmd.response <- commandResult{snapshot: item.session.Snapshot(), err: err}
		case commandRegisterCleanup:
			item.steps = append(item.steps, cleanupStep{name: cmd.cleanupName, fn: cmd.cleanup})
			cmd.response <- commandResult{snapshot: item.session.Snapshot()}
		case commandCleanup:
			snapshot, err := m.cleanup(item)
			cmd.response <- commandResult{snapshot: snapshot, err: err}
			if err == nil {
				m.finish(item, snapshot)
				close(item.done)
				return
			}
		}
	}
}

func (m *Manager) cleanup(item *entry) (Snapshot, error) {
	current := item.session.Snapshot()
	if current.Phase == PhaseDestroyed {
		if err := m.store.Remove(current.ID); err != nil {
			return current, err
		}
		return current, nil
	}
	if current.Phase != PhaseAborting && current.Phase != PhaseStopping && current.Phase != PhaseDestroying {
		if err := item.session.transition(PhaseAborting, "SESSION_ABORTING", "Session cleanup requested.", "", m.now().UTC()); err != nil {
			return item.session.Snapshot(), err
		}
		if err := m.store.Save(item.session.Snapshot()); err != nil {
			return item.session.Snapshot(), err
		}
	}
	if item.session.Snapshot().Phase != PhaseDestroying {
		if err := item.session.transition(PhaseDestroying, "SESSION_DESTROYING", "Owned resources are being released.", "", m.now().UTC()); err != nil {
			return item.session.Snapshot(), err
		}
		if err := m.store.Save(item.session.Snapshot()); err != nil {
			return item.session.Snapshot(), err
		}
	}
	var cleanupErrors []error
	cleanupContext, cancel := context.WithTimeout(context.Background(), m.cleanupWait)
	defer cancel()
	for i := len(item.steps) - 1; i >= 0; i-- {
		step := &item.steps[i]
		if step.done {
			continue
		}
		if err := step.fn(cleanupContext); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("%s: %w", step.name, err))
			continue
		}
		step.done = true
	}
	if len(cleanupErrors) > 0 {
		return item.session.Snapshot(), fmt.Errorf("cleanup incomplete: %w", errors.Join(cleanupErrors...))
	}
	if err := item.session.transition(PhaseDestroyed, "SESSION_DESTROYED", "Resource cleanup audit completed.", "", m.now().UTC()); err != nil {
		return item.session.Snapshot(), err
	}
	final := item.session.Snapshot()
	if err := m.store.Save(final); err != nil {
		return final, err
	}
	if err := m.store.Remove(final.ID); err != nil {
		return final, err
	}
	return final, nil
}

func (m *Manager) finish(item *entry, snapshot Snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries[snapshot.ID] == item {
		delete(m.entries, snapshot.ID)
	}
	if len(m.destroyed) >= 1024 {
		var oldestID string
		var oldest time.Time
		for id, candidate := range m.destroyed {
			if oldestID == "" || candidate.UpdatedAt.Before(oldest) {
				oldestID, oldest = id, candidate.UpdatedAt
			}
		}
		delete(m.destroyed, oldestID)
	}
	m.destroyed[snapshot.ID] = snapshot
}

func (m *Manager) destroyedSnapshot(id string, requesterUID uint32) (Snapshot, bool) {
	m.mu.RLock()
	snapshot, ok := m.destroyed[id]
	m.mu.RUnlock()
	if !ok || (requesterUID != 0 && requesterUID != snapshot.OwnerUID) {
		return Snapshot{}, false
	}
	return snapshot, true
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate session identifier: %w", err)
	}
	return "pvm-" + hex.EncodeToString(raw[:]), nil
}
