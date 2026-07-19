//go:build !linux

package network

import "os"

func duplicateTAPFile(*os.File) (*os.File, error) {
	return nil, ErrBackendUnavailable
}
