//go:build !linux

package cli

import (
	"context"
	"errors"
)

func launchRemoteViewer(context.Context, string) error {
	return errors.New("remote-viewer is supported only on Linux")
}
