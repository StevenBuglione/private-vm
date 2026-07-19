//go:build !linux

package policy

import (
	"errors"
	"os"
)

func openPolicyFile(string) (*os.File, error) {
	return nil, errors.New("policy file trust is unavailable on this platform")
}
