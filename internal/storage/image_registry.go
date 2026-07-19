package storage

import (
	"errors"
	"path/filepath"
	"sort"
	"sync"
)

// ImageUseRegistry prevents qemu-img from inspecting or modifying an image
// while QEMU owns it. Read-only base images may be active in more than one VM,
// but no tooling operation overlaps any active use.
type ImageUseRegistry struct {
	mu      sync.Mutex
	active  map[string]uint32
	tooling map[string]bool
}

type ImageLease struct {
	mu       sync.Mutex
	registry *ImageUseRegistry
	paths    []string
	released bool
}

func NewImageUseRegistry() *ImageUseRegistry {
	return &ImageUseRegistry{active: make(map[string]uint32), tooling: make(map[string]bool)}
}

func (r *ImageUseRegistry) withTool(paths []string, operation func() error) error {
	clean, err := cleanImagePaths(paths)
	if err != nil || operation == nil {
		return errors.New("image tooling requires clean paths and an operation")
	}
	r.mu.Lock()
	for _, path := range clean {
		if r.active[path] != 0 || r.tooling[path] {
			r.mu.Unlock()
			return errors.New("qemu-img cannot touch an active or concurrently inspected image")
		}
	}
	for _, path := range clean {
		r.tooling[path] = true
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		for _, path := range clean {
			delete(r.tooling, path)
		}
		r.mu.Unlock()
	}()
	return operation()
}

func (r *ImageUseRegistry) Activate(paths ...string) (*ImageLease, error) {
	if r == nil {
		return nil, errors.New("image-use registry is required")
	}
	clean, err := cleanImagePaths(paths)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, path := range clean {
		if r.tooling[path] {
			return nil, errors.New("QEMU image activation overlaps a tooling operation")
		}
	}
	for _, path := range clean {
		if r.active[path] == ^uint32(0) {
			return nil, errors.New("QEMU image lease count overflow")
		}
	}
	for _, path := range clean {
		r.active[path]++
	}
	return &ImageLease{registry: r, paths: clean}, nil
}

func (r *ImageUseRegistry) removable(paths ...string) bool {
	clean, err := cleanImagePaths(paths)
	if err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, path := range clean {
		if r.active[path] != 0 || r.tooling[path] {
			return false
		}
	}
	return true
}

func (l *ImageLease) Destroy() error {
	if l == nil || l.registry == nil {
		return errors.New("image lease is invalid")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil
	}
	l.registry.mu.Lock()
	defer l.registry.mu.Unlock()
	for _, path := range l.paths {
		if l.registry.active[path] == 0 {
			return errors.New("image lease ownership is inconsistent")
		}
	}
	for _, path := range l.paths {
		l.registry.active[path]--
		if l.registry.active[path] == 0 {
			delete(l.registry.active, path)
		}
	}
	l.released = true
	return nil
}

func (l *ImageLease) Audit() error {
	if l == nil || l.registry == nil {
		return errors.New("image lease is invalid")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.released {
		return errors.New("image lease remains active")
	}
	return nil
}

func cleanImagePaths(paths []string) ([]string, error) {
	if len(paths) == 0 || len(paths) > 8 {
		return nil, errors.New("image path set is empty or exceeds its bound")
	}
	seen := make(map[string]bool, len(paths))
	clean := make([]string, 0, len(paths))
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || seen[path] {
			return nil, errors.New("image paths must be unique clean absolute paths")
		}
		seen[path] = true
		clean = append(clean, path)
	}
	sort.Strings(clean)
	return clean, nil
}
