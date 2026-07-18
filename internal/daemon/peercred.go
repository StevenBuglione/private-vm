package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/credentials"
)

type PeerIdentity struct {
	PID uint32
	UID uint32
	GID uint32
}

type PeerAuthInfo struct {
	PeerIdentity
}

func (PeerAuthInfo) AuthType() string { return "unix-peer-credentials" }

type unixPeerCredentials struct{}

func NewUnixPeerCredentials() credentials.TransportCredentials {
	return unixPeerCredentials{}
}

func (unixPeerCredentials) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if _, ok := conn.(*net.UnixConn); !ok {
		return nil, nil, errors.New("private-vm RPC requires a Unix-domain socket")
	}
	return conn, PeerAuthInfo{PeerIdentity: PeerIdentity{PID: uint32(os.Getpid()), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}}, nil
}

func (unixPeerCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, errors.New("private-vm RPC requires a Unix-domain socket")
	}
	identity, err := socketPeerIdentity(unixConn)
	if err != nil {
		return nil, nil, err
	}
	return conn, PeerAuthInfo{PeerIdentity: identity}, nil
}

func (unixPeerCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "unix-peer-credentials", SecurityVersion: "1.0"}
}

func (unixPeerCredentials) Clone() credentials.TransportCredentials { return unixPeerCredentials{} }

func (unixPeerCredentials) OverrideServerName(string) error { return nil }

func socketPeerIdentity(conn *net.UnixConn) (PeerIdentity, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("access Unix socket descriptor: %w", err)
	}
	var credential *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return PeerIdentity{}, fmt.Errorf("inspect Unix peer credentials: %w", err)
	}
	if socketErr != nil {
		return PeerIdentity{}, fmt.Errorf("inspect Unix peer credentials: %w", socketErr)
	}
	if credential == nil || credential.Pid <= 0 {
		return PeerIdentity{}, errors.New("unix peer credentials are incomplete")
	}
	return PeerIdentity{PID: uint32(credential.Pid), UID: credential.Uid, GID: credential.Gid}, nil
}

func processGroups(identity PeerIdentity) ([]uint32, error) {
	path := "/proc/" + strconv.FormatUint(uint64(identity.PID), 10) + "/status"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("inspect peer process groups: %w", err)
	}
	var effectiveUID uint64
	var foundUID bool
	var groups []uint32
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) < 2 {
				return nil, errors.New("peer process UID record is malformed")
			}
			effectiveUID, err = strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return nil, errors.New("peer process UID record is malformed")
			}
			foundUID = true
		}
		if strings.HasPrefix(line, "Groups:") {
			for _, field := range strings.Fields(strings.TrimPrefix(line, "Groups:")) {
				value, parseErr := strconv.ParseUint(field, 10, 32)
				if parseErr != nil {
					return nil, errors.New("peer process group record is malformed")
				}
				groups = append(groups, uint32(value))
			}
		}
	}
	if !foundUID || uint32(effectiveUID) != identity.UID {
		return nil, errors.New("peer process identity changed during authorization")
	}
	return groups, nil
}
