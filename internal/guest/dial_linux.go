//go:build linux

package guest

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/mdlayher/socket"
	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

func dialVSOCK(ctx context.Context, cid, port uint32) (net.Conn, error) {
	connection, err := socket.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0, "private-vm-vsock", nil)
	if err != nil {
		return nil, fmt.Errorf("create AF_VSOCK socket: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = connection.Close()
		}
	}()

	remoteSockaddr := &unix.SockaddrVM{CID: cid, Port: port}
	connectedSockaddr, err := connection.Connect(ctx, remoteSockaddr)
	if err != nil {
		return nil, fmt.Errorf("connect AF_VSOCK: %w", err)
	}
	if connectedSockaddr == nil {
		connectedSockaddr = remoteSockaddr
	}
	localSockaddr, err := connection.Getsockname()
	if err != nil {
		return nil, fmt.Errorf("inspect local AF_VSOCK address: %w", err)
	}
	local, ok := localSockaddr.(*unix.SockaddrVM)
	if !ok {
		return nil, errors.New("kernel returned an unexpected local AF_VSOCK address")
	}
	remote, ok := connectedSockaddr.(*unix.SockaddrVM)
	if !ok {
		return nil, errors.New("kernel returned an unexpected remote AF_VSOCK address")
	}
	closeOnError = false
	return &addressedConn{
		connection: connection,
		local:      &vsock.Addr{ContextID: local.CID, Port: local.Port},
		remote:     &vsock.Addr{ContextID: remote.CID, Port: remote.Port},
	}, nil
}
