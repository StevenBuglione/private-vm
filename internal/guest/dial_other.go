//go:build !linux

package guest

import (
	"context"
	"errors"
	"net"
)

func dialVSOCK(context.Context, uint32, uint32) (net.Conn, error) {
	return nil, errors.New("AF_VSOCK is only supported on Linux")
}
