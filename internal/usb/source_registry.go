package usb

import (
	"context"
	"errors"
	"sync"

	"github.com/StevenBuglione/private-vm/internal/session"
)

// ApprovedSourceFactory is registered only by an authenticated role runtime
// after its report/export-state checks pass. It captures no host pathname.
type ApprovedSourceFactory func(context.Context) (ApprovedSource, error)

// ApprovedSourceRegistry is a volatile, one-use handoff between the scanner or
// workstation runtime and the exporter. A daemon restart intentionally loses
// every registration.
type ApprovedSourceRegistry struct {
	mu      sync.Mutex
	sources map[SourceSelection]ApprovedSourceFactory
}

func NewApprovedSourceRegistry() *ApprovedSourceRegistry {
	return &ApprovedSourceRegistry{sources: make(map[SourceSelection]ApprovedSourceFactory)}
}

func (registry *ApprovedSourceRegistry) Register(selection SourceSelection, factory ApprovedSourceFactory) error {
	if registry == nil || selection.validate() != nil || factory == nil {
		return errors.New("approved source registration is invalid")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.sources == nil || registry.sources[selection] != nil {
		return errors.New("approved source is already registered")
	}
	registry.sources[selection] = factory
	return nil
}

// Replace installs the newest authenticated identity for an exact source.
// It is used only after a fresh scanner report or workstation rehash proves
// that a previously registered identity is stale.
func (registry *ApprovedSourceRegistry) Replace(selection SourceSelection, factory ApprovedSourceFactory) error {
	if registry == nil || selection.validate() != nil || factory == nil {
		return errors.New("approved source registration is invalid")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.sources == nil {
		return errors.New("approved source registry is unavailable")
	}
	registry.sources[selection] = factory
	return nil
}

func (registry *ApprovedSourceRegistry) Remove(selection SourceSelection) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	delete(registry.sources, selection)
	registry.mu.Unlock()
}

// RemoveSession invalidates every volatile factory owned by one role session.
func (registry *ApprovedSourceRegistry) RemoveSession(role SourceRole, sessionID string) {
	if registry == nil || role != SourceScanner && role != SourceWorkstation || session.ValidateID(sessionID) != nil {
		return
	}
	registry.mu.Lock()
	for selection := range registry.sources {
		if selection.Role == role && selection.SessionID == sessionID {
			delete(registry.sources, selection)
		}
	}
	registry.mu.Unlock()
}

func (registry *ApprovedSourceRegistry) OpenApproved(ctx context.Context, selection SourceSelection) (ApprovedSource, error) {
	if registry == nil || selection.validate() != nil {
		return nil, errors.New("approved source selection is invalid")
	}
	registry.mu.Lock()
	factory := registry.sources[selection]
	if factory != nil {
		delete(registry.sources, selection)
	}
	registry.mu.Unlock()
	if factory == nil {
		return nil, errors.New("approved source is unavailable")
	}
	source, err := factory(ctx)
	if err != nil || source == nil {
		return nil, errors.Join(errors.New("approved source could not be opened"), err)
	}
	return source, nil
}

var _ ApprovedSourceProvider = (*ApprovedSourceRegistry)(nil)
