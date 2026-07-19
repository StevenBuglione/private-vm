//go:build !linux

package transfer

import (
	"errors"
	"os"
)

func openSourceNoFollow(string) (*os.File, error) {
	return nil, errors.New("safe source opening is supported only on Linux")
}
