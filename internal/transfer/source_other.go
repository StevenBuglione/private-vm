//go:build !linux

package transfer

import (
	"errors"
	"os"
)

func openSourceNoFollow(string) (*os.File, *os.File, error) {
	return nil, nil, errors.New("safe source opening is supported only on Linux")
}
