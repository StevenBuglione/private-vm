//go:build !linux

package secret

import "os"

func newState(value []byte) (*state, error) {
	return &state{value: append([]byte(nil), value...), fd: -1}, nil
}

func dupFile(*state) (*os.File, error) {
	return nil, ErrNotMemfd
}

func releaseState(*state) {}
