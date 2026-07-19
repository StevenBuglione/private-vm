package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"sync"
	"time"
)

const (
	DefaultMaxSessionsPerOwner = 4
	maxCommandQueue            = 64
	maxSubscribersPerSession   = 32
	maxSubscriberQueue         = 64
	maxIDAttempts              = 8
)

var resourceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)

type CleanupFunc func(context.Context) error
type AuditFunc func(context.Context) error

// AllocateFunc returns a completely owned resource with idempotent cleanup and
// absence-audit functions. When allocation fails after acquiring something it
// may return both functions with the error; the actor journals the partial
// resource for retryable cleanup before reporting ErrCleanupIncomplete. It runs
// inside the session actor so allocation and cleanup registration are one
// serialized operation.
type AllocateFunc func(context.Context) (CleanupFunc, AuditFunc, error)

type cleanupStep struct {
	name    string
	cleanup CleanupFunc
	audit   AuditFunc
	done    bool
}

type commandKind uint8

const (
	commandTransition commandKind = iota + 1
	commandWorkflow
	commandAcquire
	commandSubscribe
	commandCleanup
)

type command struct {
	kind       commandKind
	to         Phase
	workflow   string
	resource   string
	allocate   AllocateFunc
	operation  context.Context
	after      uint64
	cleanupRun *cleanupAttempt
	response   chan commandResult
}

type commandResult struct {
	snapshot     Snapshot
	subscription *Subscription
	err          error
}

type cleanupAttempt struct {
	done   chan struct{}
	result commandResult
}

type subscriberState struct {
	mu     sync.Mutex
	id     uint64
	events chan Event
	cancel chan struct{}
	done   chan struct{}
	err    error
	once   sync.Once
}

func (s *subscriberState) finish(err error) {
	s.once.Do(func() {
		s.mu.Lock()
		s.err = err
		s.mu.Unlock()
		close(s.events)
		close(s.done)
	})
}

type Subscription struct {
	snapshot    Snapshot
	replay      []Event
	state       *subscriberState
	unsubscribe chan<- uint64
	closeOnce   sync.Once
}

func (s *Subscription) Snapshot() Snapshot    { return cloneSnapshot(s.snapshot) }
func (s *Subscription) Replay() []Event       { return append([]Event(nil), s.replay...) }
func (s *Subscription) Events() <-chan Event  { return s.state.events }
func (s *Subscription) Done() <-chan struct{} { return s.state.done }

func (s *Subscription) Err() error {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	return s.state.err
}

func (s *Subscription) Close() {
	s.closeOnce.Do(func() {
		close(s.state.cancel)
		select {
		case s.unsubscribe <- s.state.id:
		default:
			// The cancel channel is also checked before every publication. The
			// bounded unsubscribe queue can be full only when the owner is busy.
		}
	})
}

type entry struct {
	session     *Session
	commands    chan command
	unsubscribe chan uint64
	done        chan struct{}
	steps       []cleanupStep
	subscribers map[uint64]*subscriberState
	nextSubID   uint64
	accepting   bool

	cleanupMu sync.Mutex
	cleanup   *cleanupAttempt
}

type Manager struct {
	store       *Store
	maxPerOwner int
	now         func() time.Time
	cleanupWait time.Duration
	newID       func() (string, error)

	mu           sync.RWMutex
	entries      map[string]*entry
	destroyed    map[string]Snapshot
	shuttingDown bool
}

func NewManager(store *Store, maxPerOwner int) (*Manager, error) {
	if store == nil {
		return nil, errors.New("session store is required")
	}
	if maxPerOwner < 1 || maxPerOwner > 64 {
		return nil, errors.New("per-owner session quota must be between 1 and 64")
	}
	return &Manager{
		store: store, maxPerOwner: maxPerOwner, now: time.Now,
		cleanupWait: 30 * time.Second, newID: randomID,
		entries: make(map[string]*entry), destroyed: make(map[string]Snapshot),
	}, nil
}

func (m *Manager) Create(ownerUID uint32, role Role) (Snapshot, error) {
	if err := ValidateRole(role); err != nil {
		return Snapshot{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shuttingDown {
		return Snapshot{}, ErrManagerShuttingDown
	}
	count := 0
	for _, item := range m.entries {
		if item.session.Snapshot().OwnerUID == ownerUID {
			count++
		}
	}
	if count >= m.maxPerOwner {
		return Snapshot{}, ErrQuotaExceeded
	}
	for attempt := 0; attempt < maxIDAttempts; attempt++ {
		id, err := m.newID()
		if err != nil {
			return Snapshot{}, err
		}
		if _, exists := m.entries[id]; exists {
			continue
		}
		s, err := newOwned(id, ownerUID, role, m.now().UTC())
		if err != nil {
			return Snapshot{}, err
		}
		snapshot := s.Snapshot()
		if err := m.store.Create(snapshot); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return Snapshot{}, err
		}
		item := &entry{
			session: s, commands: make(chan command, maxCommandQueue),
			unsubscribe: make(chan uint64, maxSubscribersPerSession*2),
			done:        make(chan struct{}), subscribers: make(map[uint64]*subscriberState),
			accepting: true,
		}
		m.entries[id] = item
		go m.run(item)
		return snapshot, nil
	}
	return Snapshot{}, errors.New("could not allocate a collision-free session identifier")
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
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}

func (m *Manager) Transition(ctx context.Context, id string, requesterUID uint32, to Phase) (Snapshot, error) {
	return m.send(ctx, id, requesterUID, command{kind: commandTransition, to: to})
}

func (m *Manager) TransitionWorkflow(ctx context.Context, id string, requesterUID uint32, to string) (Snapshot, error) {
	if !eventCodePattern.MatchString(to) {
		return Snapshot{}, ErrInvalidWorkflow
	}
	return m.send(ctx, id, requesterUID, command{kind: commandWorkflow, workflow: to})
}

func (m *Manager) AcquireResource(ctx context.Context, id string, requesterUID uint32, name string, allocate AllocateFunc) error {
	if !resourceNamePattern.MatchString(name) || allocate == nil {
		return errors.New("resource name and allocator are required")
	}
	_, err := m.send(ctx, id, requesterUID, command{
		kind: commandAcquire, resource: name, allocate: allocate, operation: ctx,
	})
	return err
}

func (m *Manager) Subscribe(ctx context.Context, id string, requesterUID uint32, after uint64) (*Subscription, error) {
	item, err := m.authorizedEntry(id, requesterUID)
	if err != nil {
		return nil, err
	}
	cmd := command{kind: commandSubscribe, after: after, response: make(chan commandResult, 1)}
	select {
	case item.commands <- cmd:
	case <-item.done:
		return nil, ErrNotFound
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case result := <-cmd.response:
		return result.subscription, result.err
	case <-item.done:
		return nil, ErrNotFound
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *Manager) Cleanup(ctx context.Context, id string, requesterUID uint32) (Snapshot, error) {
	if snapshot, ok := m.destroyedSnapshot(id, requesterUID); ok {
		return snapshot, nil
	}
	item, err := m.authorizedEntry(id, requesterUID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			if snapshot, ok := m.destroyedSnapshot(id, requesterUID); ok {
				return snapshot, nil
			}
		}
		return Snapshot{}, err
	}
	attempt := m.requestCleanup(item)
	select {
	case <-attempt.done:
		return attempt.result.snapshot, attempt.result.err
	case <-ctx.Done():
		// Once the cleanup command is admitted, the actor retains ownership and
		// continues independently of this caller's lifetime.
		return Snapshot{}, ctx.Err()
	}
}

func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.shuttingDown = true
	type pendingCleanup struct {
		id      string
		attempt *cleanupAttempt
	}
	entries := make([]struct {
		id   string
		item *entry
	}, 0, len(m.entries))
	for id, item := range m.entries {
		entries = append(entries, struct {
			id   string
			item *entry
		}{id: id, item: item})
	}
	m.mu.Unlock()
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })

	// Admit cleanup for every actor before waiting for any one actor. Admission
	// and execution are daemon-owned and therefore continue after the shutdown
	// caller's bounded wait expires.
	pending := make([]pendingCleanup, 0, len(entries))
	for _, candidate := range entries {
		pending = append(pending, pendingCleanup{
			id: candidate.id, attempt: m.requestCleanup(candidate.item),
		})
	}

	var cleanupErrors []error
	for _, candidate := range pending {
		select {
		case <-candidate.attempt.done:
			if err := candidate.attempt.result.err; err != nil && !errors.Is(err, ErrNotFound) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("session %s: %w", candidate.id, err))
			}
		case <-ctx.Done():
			cleanupErrors = append(cleanupErrors, ctx.Err())
			return fmt.Errorf("%w", errors.Join(append([]error{ErrCleanupIncomplete}, cleanupErrors...)...))
		}
	}
	if len(cleanupErrors) != 0 {
		return fmt.Errorf("%w", errors.Join(append([]error{ErrCleanupIncomplete}, cleanupErrors...)...))
	}
	return nil
}

// requestCleanup establishes daemon ownership before returning. The admission
// goroutine is intentionally independent of request and shutdown contexts: a
// disconnected client may stop waiting, but it cannot revoke cleanup.
func (m *Manager) requestCleanup(item *entry) *cleanupAttempt {
	attempt, first := item.beginCleanup()
	if !first {
		return attempt
	}
	go func() {
		select {
		case item.commands <- command{kind: commandCleanup, cleanupRun: attempt}:
		case <-item.done:
			item.completeCleanup(attempt, commandResult{err: ErrNotFound})
		}
	}()
	return attempt
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
	case <-item.done:
		return Snapshot{}, ErrNotFound
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	}
}

func (m *Manager) authorizedEntry(id string, requesterUID uint32) (*entry, error) {
	if err := ValidateID(id); err != nil {
		return nil, ErrNotFound
	}
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
	for {
		select {
		case subscriberID := <-item.unsubscribe:
			item.removeSubscriber(subscriberID, nil)
		case cmd := <-item.commands:
			switch cmd.kind {
			case commandTransition:
				snapshot, err := m.transition(item, cmd.to, false)
				cmd.response <- commandResult{snapshot: snapshot, err: err}
			case commandWorkflow:
				snapshot, err := m.workflow(item, cmd.workflow)
				cmd.response <- commandResult{snapshot: snapshot, err: err}
			case commandAcquire:
				err := m.acquire(item, cmd)
				cmd.response <- commandResult{snapshot: item.session.Snapshot(), err: err}
			case commandSubscribe:
				subscription, err := item.subscribe(cmd.after)
				cmd.response <- commandResult{snapshot: item.session.Snapshot(), subscription: subscription, err: err}
			case commandCleanup:
				snapshot, err := m.cleanupEntry(item)
				result := commandResult{snapshot: snapshot, err: err}
				if err == nil {
					m.finish(item, snapshot)
					item.completeCleanup(cmd.cleanupRun, result)
					item.closeSubscribers(nil)
					close(item.done)
					return
				}
				item.completeCleanup(cmd.cleanupRun, result)
			}
		}
	}
}

func (m *Manager) transition(item *entry, to Phase, cleanupOwned bool) (Snapshot, error) {
	before := item.session.Snapshot()
	event, err := item.session.transitionLifecycle(to, cleanupOwned, m.now().UTC())
	if err != nil {
		return before, err
	}
	after := item.session.Snapshot()
	if err := m.store.Save(after); err != nil {
		item.session.restore(before)
		return before, err
	}
	item.publish(event)
	return after, nil
}

func (m *Manager) workflow(item *entry, to string) (Snapshot, error) {
	before := item.session.Snapshot()
	event, err := item.session.transitionWorkflow(to, m.now().UTC())
	if err != nil {
		return before, err
	}
	after := item.session.Snapshot()
	if err := m.store.Save(after); err != nil {
		item.session.restore(before)
		return before, err
	}
	item.publish(event)
	return after, nil
}

func (m *Manager) acquire(item *entry, cmd command) error {
	if !item.accepting {
		return ErrResourceRegistrationEnd
	}
	phase := item.session.Snapshot().Phase
	if phase == PhaseStopping || phase == PhaseAborting || phase == PhaseDestroying || phase == PhaseDestroyed {
		return ErrResourceRegistrationEnd
	}
	for _, step := range item.steps {
		if step.name == cmd.resource {
			return ErrDuplicateResource
		}
	}
	cleanup, audit, err := cmd.allocate(cmd.operation)
	if err != nil {
		if cleanup == nil && audit == nil {
			return err
		}
		if cleanup == nil || audit == nil {
			return errors.Join(err, errors.New("allocator returned an incomplete partial-resource contract"))
		}
		item.steps = append(item.steps, cleanupStep{name: cmd.resource, cleanup: cleanup, audit: audit})
		return errors.Join(err, ErrCleanupIncomplete)
	}
	if cleanup == nil || audit == nil {
		return errors.New("allocator returned an incomplete resource contract")
	}
	step := cleanupStep{name: cmd.resource, cleanup: cleanup, audit: audit}
	if err := cmd.operation.Err(); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), m.cleanupWait)
		defer cancel()
		if cleanupErr := step.cleanup(rollbackCtx); cleanupErr != nil {
			item.steps = append(item.steps, step)
			return ErrCleanupIncomplete
		}
		if auditErr := step.audit(rollbackCtx); auditErr != nil {
			item.steps = append(item.steps, step)
			return ErrCleanupIncomplete
		}
		return err
	}
	item.steps = append(item.steps, step)
	return nil
}

func (m *Manager) cleanupEntry(item *entry) (Snapshot, error) {
	item.accepting = false
	current := item.session.Snapshot()
	if current.Phase != PhaseStopping && current.Phase != PhaseAborting && current.Phase != PhaseDestroying {
		var err error
		current, err = m.transition(item, PhaseAborting, true)
		if err != nil {
			return current, err
		}
	}
	if current.Phase != PhaseDestroying {
		var err error
		current, err = m.transition(item, PhaseDestroying, true)
		if err != nil {
			return current, err
		}
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), m.cleanupWait)
	defer cancel()
	for index := len(item.steps) - 1; index >= 0; index-- {
		step := &item.steps[index]
		if step.done {
			continue
		}
		if err := step.cleanup(cleanupCtx); err != nil {
			return item.session.Snapshot(), ErrCleanupIncomplete
		}
		// A cleanup step is complete only after its absence audit succeeds. If
		// the audit fails, leave the idempotent step retryable so a later cleanup
		// request can converge rather than permanently skipping the resource.
		if err := step.audit(cleanupCtx); err != nil {
			return item.session.Snapshot(), ErrCleanupIncomplete
		}
		step.done = true
	}
	if err := m.store.Remove(current.ID); err != nil {
		return item.session.Snapshot(), ErrCleanupIncomplete
	}
	// The volatile record is itself a resource. Only after it is absent may the
	// actor commit and publish the terminal DESTROYED event.
	event, err := item.session.transitionLifecycle(PhaseDestroyed, true, m.now().UTC())
	if err != nil {
		return item.session.Snapshot(), err
	}
	item.publish(event)
	return item.session.Snapshot(), nil
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
	tombstone := snapshot
	tombstone.Events = nil
	m.destroyed[snapshot.ID] = tombstone
}

func (m *Manager) destroyedSnapshot(id string, requesterUID uint32) (Snapshot, bool) {
	m.mu.RLock()
	snapshot, ok := m.destroyed[id]
	m.mu.RUnlock()
	if !ok || (requesterUID != 0 && requesterUID != snapshot.OwnerUID) {
		return Snapshot{}, false
	}
	return cloneSnapshot(snapshot), true
}

func (item *entry) beginCleanup() (*cleanupAttempt, bool) {
	item.cleanupMu.Lock()
	defer item.cleanupMu.Unlock()
	if item.cleanup != nil {
		return item.cleanup, false
	}
	attempt := &cleanupAttempt{done: make(chan struct{})}
	item.cleanup = attempt
	return attempt, true
}

func (item *entry) completeCleanup(attempt *cleanupAttempt, result commandResult) {
	item.cleanupMu.Lock()
	defer item.cleanupMu.Unlock()
	if item.cleanup != attempt {
		return
	}
	attempt.result = result
	item.cleanup = nil
	close(attempt.done)
}

func (item *entry) subscribe(after uint64) (*Subscription, error) {
	snapshot := item.session.Snapshot()
	if after > snapshot.Sequence {
		return nil, ErrEventCursor
	}
	if len(item.subscribers) >= maxSubscribersPerSession {
		return nil, ErrSubscriberSlow
	}
	item.nextSubID++
	state := &subscriberState{
		id: item.nextSubID, events: make(chan Event, maxSubscriberQueue),
		cancel: make(chan struct{}), done: make(chan struct{}),
	}
	item.subscribers[state.id] = state
	replay := make([]Event, 0, len(snapshot.Events))
	for _, event := range snapshot.Events {
		if event.Sequence > after {
			replay = append(replay, event)
		}
	}
	return &Subscription{
		snapshot: cloneSnapshot(snapshot), replay: replay, state: state,
		unsubscribe: item.unsubscribe,
	}, nil
}

func (item *entry) publish(event Event) {
	for id, subscriber := range item.subscribers {
		select {
		case <-subscriber.cancel:
			item.removeSubscriber(id, nil)
			continue
		default:
		}
		select {
		case subscriber.events <- event:
		default:
			item.removeSubscriber(id, ErrSubscriberSlow)
		}
	}
}

func (item *entry) removeSubscriber(id uint64, err error) {
	state := item.subscribers[id]
	if state == nil {
		return
	}
	delete(item.subscribers, id)
	state.finish(err)
}

func (item *entry) closeSubscribers(err error) {
	for id := range item.subscribers {
		item.removeSubscriber(id, err)
	}
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	snapshot.Events = append([]Event(nil), snapshot.Events...)
	return snapshot
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate session identifier: %w", err)
	}
	return "pvm-" + hex.EncodeToString(raw[:]), nil
}
