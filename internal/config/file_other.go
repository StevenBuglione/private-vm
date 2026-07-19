//go:build !linux

package config

import (
	"errors"
	"os"
)

func openConfigFile(string, FileTrust) (*os.File, error) {
	return nil, errors.New("configuration file trust is unavailable on this platform")
}
