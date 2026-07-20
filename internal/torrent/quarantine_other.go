//go:build !linux

package torrent

import (
	"context"
	"errors"
)

func PrepareLinuxQuarantine(context.Context, string, int, int) (*QuarantineOwner, error) {
	return nil, errors.New("downloader quarantine is supported only in the Linux guest")
}
