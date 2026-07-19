package usb

import (
	"context"
	"errors"
	"sync"
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

func (registry *ApprovedSourceRegistry) Remove(selection SourceSelection) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	delete(registry.sources, selection)
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
