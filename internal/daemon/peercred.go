package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/credentials"
)

type PeerIdentity struct {
	PID            uint32
	UID            uint32
	GID            uint32
	StartTimeTicks uint64
}

const (
	maxProcStatBytes   = 64 << 10
	maxProcStatusBytes = 2 << 20
	maxPidfdInfoBytes  = 4 << 10
)

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
		if wrapped, wrappedOK := conn.(interface{ privateVMUnixConn() *net.UnixConn }); wrappedOK {
			unixConn = wrapped.privateVMUnixConn()
			ok = unixConn != nil
		}
	}
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
	peerPIDFD := -1
	var socketErr error
	controlErr := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if socketErr != nil {
			return
		}
		peerPIDFD, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
		if socketErr == nil && peerPIDFD >= 0 {
			unix.CloseOnExec(peerPIDFD)
		}
	})
	if controlErr != nil {
		if peerPIDFD >= 0 {
			_ = unix.Close(peerPIDFD)
		}
		return PeerIdentity{}, fmt.Errorf("inspect Unix peer credentials: %w", controlErr)
	}
	if socketErr != nil {
		if peerPIDFD >= 0 {
			_ = unix.Close(peerPIDFD)
		}
		return PeerIdentity{}, fmt.Errorf("inspect Unix peer credentials: %w", socketErr)
	}
	if peerPIDFD < 0 {
		return PeerIdentity{}, errors.New("unix peer pidfd is unavailable")
	}
	defer unix.Close(peerPIDFD)
	if credential == nil || credential.Pid <= 0 {
		return PeerIdentity{}, errors.New("unix peer credentials are incomplete")
	}

	pid := uint32(credential.Pid)
	if err := verifyPidfdTarget(peerPIDFD, pid); err != nil {
		return PeerIdentity{}, err
	}
	stat, err := readBoundedProcFile(procPIDPath(pid, "stat"), maxProcStatBytes)
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("inspect Unix peer start time: %w", err)
	}
	statPID, startTime, err := parseProcStat(stat)
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("inspect Unix peer start time: %w", err)
	}
	if statPID != pid {
		return PeerIdentity{}, errors.New("unix peer process identity changed during credential capture")
	}
	if err := verifyPidfdTarget(peerPIDFD, pid); err != nil {
		return PeerIdentity{}, err
	}

	return PeerIdentity{
		PID:            pid,
		UID:            credential.Uid,
		GID:            credential.Gid,
		StartTimeTicks: startTime,
	}, nil
}

func processGroups(identity PeerIdentity) ([]uint32, error) {
	if identity.PID == 0 || identity.StartTimeTicks == 0 {
		return nil, errors.New("peer process identity is incomplete")
	}
	if err := verifyProcStatIdentity(identity); err != nil {
		return nil, err
	}
	data, err := readBoundedProcFile(procPIDPath(identity.PID, "status"), maxProcStatusBytes)
	if err != nil {
		return nil, fmt.Errorf("inspect peer process groups: %w", err)
	}
	statusPID, effectiveUID, groups, err := parseProcStatus(data)
	if err != nil {
		return nil, err
	}
	if statusPID != identity.PID || effectiveUID != identity.UID {
		return nil, errors.New("peer process identity changed during authorization")
	}
	if err := verifyProcStatIdentity(identity); err != nil {
		return nil, err
	}
	return groups, nil
}

func verifyPidfdTarget(pidfd int, expectedPID uint32) error {
	data, err := readBoundedProcFile("/proc/self/fdinfo/"+strconv.Itoa(pidfd), maxPidfdInfoBytes)
	if err != nil {
		return fmt.Errorf("inspect Unix peer pidfd: %w", err)
	}
	pid, err := parsePidfdInfo(data)
	if err != nil {
		return fmt.Errorf("inspect Unix peer pidfd: %w", err)
	}
	if pid != expectedPID {
		return errors.New("unix peer process identity changed during credential capture")
	}
	return nil
}

func verifyProcStatIdentity(identity PeerIdentity) error {
	data, err := readBoundedProcFile(procPIDPath(identity.PID, "stat"), maxProcStatBytes)
	if err != nil {
		return fmt.Errorf("inspect peer process identity: %w", err)
	}
	pid, startTime, err := parseProcStat(data)
	if err != nil {
		return fmt.Errorf("inspect peer process identity: %w", err)
	}
	if pid != identity.PID || startTime != identity.StartTimeTicks {
		return errors.New("peer process identity changed during authorization")
	}
	return nil
}

func procPIDPath(pid uint32, name string) string {
	return "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/" + name
}

func readBoundedProcFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("process evidence exceeds the supported bound")
	}
	return data, nil
}

func parseProcStat(data []byte) (uint32, uint64, error) {
	if len(data) == 0 || len(data) > maxProcStatBytes || bytes.IndexByte(data, 0) >= 0 {
		return 0, 0, errors.New("peer process stat record is malformed")
	}
	open := bytes.IndexByte(data, '(')
	close := bytes.LastIndexByte(data, ')')
	if open <= 0 || close <= open || close+1 >= len(data) {
		return 0, 0, errors.New("peer process stat record is malformed")
	}
	pidValue, err := strconv.ParseUint(strings.TrimSpace(string(data[:open])), 10, 32)
	if err != nil || pidValue == 0 {
		return 0, 0, errors.New("peer process stat PID is malformed")
	}
	fields := strings.Fields(string(data[close+1:]))
	// fields starts at stat field 3 (state); starttime is stat field 22.
	if len(fields) <= 19 {
		return 0, 0, errors.New("peer process stat record is incomplete")
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTime == 0 {
		return 0, 0, errors.New("peer process start time is invalid")
	}
	return uint32(pidValue), startTime, nil
}

func parsePidfdInfo(data []byte) (uint32, error) {
	if len(data) == 0 || len(data) > maxPidfdInfoBytes || bytes.IndexByte(data, 0) >= 0 {
		return 0, errors.New("peer pidfd record is malformed")
	}
	var pid uint32
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Pid:") {
			continue
		}
		if found {
			return 0, errors.New("peer pidfd record contains duplicate PID evidence")
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Pid:"))
		if len(fields) != 1 {
			return 0, errors.New("peer pidfd PID record is malformed")
		}
		value, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil || value == 0 {
			return 0, errors.New("peer pidfd PID record is malformed")
		}
		pid = uint32(value)
		found = true
	}
	if !found {
		return 0, errors.New("peer pidfd PID record is absent")
	}
	return pid, nil
}

func parseProcStatus(data []byte) (uint32, uint32, []uint32, error) {
	if len(data) == 0 || len(data) > maxProcStatusBytes || bytes.IndexByte(data, 0) >= 0 {
		return 0, 0, nil, errors.New("peer process status record is malformed")
	}
	var pid uint32
	var effectiveUID uint32
	var groups []uint32
	foundPID := false
	foundUID := false
	foundGroups := false
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "Pid:"):
			if foundPID {
				return 0, 0, nil, errors.New("peer process status contains duplicate PID evidence")
			}
			fields := strings.Fields(strings.TrimPrefix(line, "Pid:"))
			if len(fields) != 1 {
				return 0, 0, nil, errors.New("peer process PID record is malformed")
			}
			value, err := strconv.ParseUint(fields[0], 10, 32)
			if err != nil || value == 0 {
				return 0, 0, nil, errors.New("peer process PID record is malformed")
			}
			pid = uint32(value)
			foundPID = true
		case strings.HasPrefix(line, "Uid:"):
			if foundUID {
				return 0, 0, nil, errors.New("peer process status contains duplicate UID evidence")
			}
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) != 4 {
				return 0, 0, nil, errors.New("peer process UID record is malformed")
			}
			value, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return 0, 0, nil, errors.New("peer process UID record is malformed")
			}
			effectiveUID = uint32(value)
			foundUID = true
		case strings.HasPrefix(line, "Groups:"):
			if foundGroups {
				return 0, 0, nil, errors.New("peer process status contains duplicate group evidence")
			}
			fields := strings.Fields(strings.TrimPrefix(line, "Groups:"))
			groups = make([]uint32, 0, len(fields))
			for _, field := range fields {
				value, err := strconv.ParseUint(field, 10, 32)
				if err != nil {
					return 0, 0, nil, errors.New("peer process group record is malformed")
				}
				groups = append(groups, uint32(value))
			}
			foundGroups = true
		}
	}
	if !foundPID || !foundUID || !foundGroups {
		return 0, 0, nil, errors.New("peer process status evidence is incomplete")
	}
	return pid, effectiveUID, groups, nil
}
