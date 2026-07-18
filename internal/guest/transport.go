package guest

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc/credentials"
)

type vsockTransportCredentials struct{}

type vsockAuthInfo struct{}

func (vsockAuthInfo) AuthType() string { return "private-vm-vsock" }

func VSOCKTransportCredentials() credentials.TransportCredentials {
	return vsockTransportCredentials{}
}

func (vsockTransportCredentials) ClientHandshake(ctx context.Context, _ string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if !isVSOCKConn(rawConn) {
		return nil, nil, errors.New("guest gRPC transport must use AF_VSOCK")
	}
	return rawConn, vsockAuthInfo{}, nil
}

func (vsockTransportCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if !isVSOCKConn(rawConn) {
		return nil, nil, errors.New("guest gRPC transport must use AF_VSOCK")
	}
	return rawConn, vsockAuthInfo{}, nil
}

func (vsockTransportCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "private-vm-vsock"}
}

func (vsockTransportCredentials) Clone() credentials.TransportCredentials {
	return vsockTransportCredentials{}
}

func (vsockTransportCredentials) OverrideServerName(string) error {
	return errors.New("server-name overrides are not supported for AF_VSOCK")
}

func isVSOCKConn(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	_, localOK := conn.LocalAddr().(*vsock.Addr)
	_, remoteOK := conn.RemoteAddr().(*vsock.Addr)
	return localOK && remoteOK
}

type addressedConn struct {
	connection deadlineConn
	local      *vsock.Addr
	remote     *vsock.Addr
}

type deadlineConn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func (c *addressedConn) Read(buffer []byte) (int, error)  { return c.connection.Read(buffer) }
func (c *addressedConn) Write(buffer []byte) (int, error) { return c.connection.Write(buffer) }
func (c *addressedConn) Close() error                     { return c.connection.Close() }
func (c *addressedConn) LocalAddr() net.Addr              { return c.local }
func (c *addressedConn) RemoteAddr() net.Addr             { return c.remote }
func (c *addressedConn) SetDeadline(deadline time.Time) error {
	return c.connection.SetDeadline(deadline)
}
func (c *addressedConn) SetReadDeadline(deadline time.Time) error {
	return c.connection.SetReadDeadline(deadline)
}
func (c *addressedConn) SetWriteDeadline(deadline time.Time) error {
	return c.connection.SetWriteDeadline(deadline)
}
