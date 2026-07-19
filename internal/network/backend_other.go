//go:build !linux

package network

func newPlatformBackend(ToolPaths) (backend, error) {
	return nil, ErrBackendUnavailable
}
