package daemon

import (
	"bytes"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestParseProcStat(t *testing.T) {
	data := procStatFixture(123, "name ) with spaces", 4242)
	pid, startTime, err := parseProcStat(data)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 123 || startTime != 4242 {
		t.Fatalf("parsed stat identity = (%d, %d), want (123, 4242)", pid, startTime)
	}
}

func TestParseProcStatRejectsMalformedEvidence(t *testing.T) {
	tests := map[string][]byte{
		"empty":           nil,
		"oversized":       bytes.Repeat([]byte{'x'}, maxProcStatBytes+1),
		"embedded-nul":    append(procStatFixture(123, "peer", 4242), 0),
		"missing-command": []byte("123 S 1 2 3"),
		"invalid-pid":     procStatFixtureText("invalid", "peer", "4242"),
		"zero-pid":        procStatFixture(0, "peer", 4242),
		"incomplete":      []byte("123 (peer) S 1 2 3"),
		"invalid-start":   procStatFixtureText("123", "peer", "invalid"),
		"zero-start":      procStatFixture(123, "peer", 0),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseProcStat(data); err == nil {
				t.Fatal("malformed stat evidence was accepted")
			}
		})
	}
}

func TestParseProcStatus(t *testing.T) {
	data := []byte("Name:\tpeer\nPid:\t123\nUid:\t1000\t1001\t1002\t1003\nGroups:\t7 8 4242\n")
	pid, effectiveUID, groups, err := parseProcStatus(data)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 123 || effectiveUID != 1001 || !slices.Equal(groups, []uint32{7, 8, 4242}) {
		t.Fatalf("parsed status = pid %d uid %d groups %v", pid, effectiveUID, groups)
	}
}

func TestParseProcStatusAcceptsVerifiedEmptySupplementaryGroups(t *testing.T) {
	data := []byte("Pid:\t123\nUid:\t1000\t1000\t1000\t1000\nGroups:\t\n")
	pid, effectiveUID, groups, err := parseProcStatus(data)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 123 || effectiveUID != 1000 || groups == nil || len(groups) != 0 {
		t.Fatalf("empty group evidence = pid %d uid %d groups %#v", pid, effectiveUID, groups)
	}
}

func TestParseProcStatusRejectsMalformedEvidence(t *testing.T) {
	valid := "Pid:\t123\nUid:\t1000\t1001\t1002\t1003\nGroups:\t7 8\n"
	tests := map[string][]byte{
		"empty":            nil,
		"oversized":        bytes.Repeat([]byte{'x'}, maxProcStatusBytes+1),
		"embedded-nul":     append([]byte(valid), 0),
		"missing-pid":      []byte("Uid:\t1000\t1001\t1002\t1003\nGroups:\t7\n"),
		"duplicate-pid":    []byte("Pid:\t123\nPid:\t123\nUid:\t1000\t1001\t1002\t1003\nGroups:\t7\n"),
		"invalid-pid":      []byte("Pid:\tinvalid\nUid:\t1000\t1001\t1002\t1003\nGroups:\t7\n"),
		"missing-uid":      []byte("Pid:\t123\nGroups:\t7\n"),
		"duplicate-uid":    []byte("Pid:\t123\nUid:\t1\t1\t1\t1\nUid:\t1\t1\t1\t1\nGroups:\t7\n"),
		"short-uid":        []byte("Pid:\t123\nUid:\t1\t1\nGroups:\t7\n"),
		"invalid-uid":      []byte("Pid:\t123\nUid:\t1\tinvalid\t1\t1\nGroups:\t7\n"),
		"missing-groups":   []byte("Pid:\t123\nUid:\t1\t1\t1\t1\n"),
		"duplicate-groups": []byte("Pid:\t123\nUid:\t1\t1\t1\t1\nGroups:\t7\nGroups:\t8\n"),
		"invalid-group":    []byte("Pid:\t123\nUid:\t1\t1\t1\t1\nGroups:\tinvalid\n"),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := parseProcStatus(data); err == nil {
				t.Fatal("malformed status evidence was accepted")
			}
		})
	}
}

func TestParsePidfdInfoRejectsMissingMalformedAndVanishedTargets(t *testing.T) {
	if pid, err := parsePidfdInfo([]byte("pos:\t0\nflags:\t02000002\nPid:\t123\n")); err != nil || pid != 123 {
		t.Fatalf("parse valid pidfd info: pid=%d err=%v", pid, err)
	}
	for name, data := range map[string][]byte{
		"missing":   []byte("pos:\t0\n"),
		"malformed": []byte("Pid:\tinvalid\n"),
		"vanished":  []byte("Pid:\t-1\n"),
		"duplicate": []byte("Pid:\t123\nPid:\t123\n"),
		"oversized": bytes.Repeat([]byte{'x'}, maxPidfdInfoBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePidfdInfo(data); err == nil {
				t.Fatal("invalid pidfd evidence was accepted")
			}
		})
	}
}

func TestProcessGroupsRevalidatesPIDUIDAndStartTime(t *testing.T) {
	identity := currentProcessIdentity(t)
	groups, err := processGroups(identity)
	if err != nil {
		t.Fatalf("resolve current process groups: %v", err)
	}
	if groups == nil {
		t.Fatal("current process group evidence is absent")
	}

	reused := identity
	reused.StartTimeTicks++
	if _, err := processGroups(reused); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("reused process identity was not rejected: %v", err)
	}

	changedUID := identity
	changedUID.UID++
	if _, err := processGroups(changedUID); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("changed peer UID was not rejected: %v", err)
	}

	vanished := PeerIdentity{PID: math.MaxUint32, UID: identity.UID, GID: identity.GID, StartTimeTicks: 1}
	if _, err := processGroups(vanished); err == nil {
		t.Fatal("vanished peer process was not rejected")
	}

	if _, err := processGroups(PeerIdentity{PID: identity.PID, UID: identity.UID, GID: identity.GID}); err == nil {
		t.Fatal("identity without captured start time was not rejected")
	}
}

func TestSocketPeerIdentityCapturesKernelBoundUnixPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientResult := make(chan struct {
		conn *net.UnixConn
		err  error
	}, 1)
	go func() {
		conn, dialErr := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		clientResult <- struct {
			conn *net.UnixConn
			err  error
		}{conn: conn, err: dialErr}
	}()

	serverConn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	client := <-clientResult
	if client.err != nil {
		t.Fatal(client.err)
	}
	defer client.conn.Close()

	identity, err := socketPeerIdentity(serverConn)
	if err != nil {
		t.Fatal(err)
	}
	if identity.PID != uint32(os.Getpid()) || identity.UID != uint32(os.Geteuid()) || identity.GID != uint32(os.Getegid()) {
		t.Fatalf("captured peer identity = %+v", identity)
	}
	if identity.StartTimeTicks == 0 {
		t.Fatal("peer start time was not captured")
	}
	if _, err := processGroups(identity); err != nil {
		t.Fatalf("revalidate connected Unix peer: %v", err)
	}
}

func currentProcessIdentity(t *testing.T) PeerIdentity {
	t.Helper()
	pid := uint32(os.Getpid())
	data, err := readBoundedProcFile(procPIDPath(pid, "stat"), maxProcStatBytes)
	if err != nil {
		t.Fatal(err)
	}
	statPID, startTime, err := parseProcStat(data)
	if err != nil {
		t.Fatal(err)
	}
	if statPID != pid {
		t.Fatalf("current stat PID = %d, want %d", statPID, pid)
	}
	return PeerIdentity{
		PID:            pid,
		UID:            uint32(os.Geteuid()),
		GID:            uint32(os.Getegid()),
		StartTimeTicks: startTime,
	}
}

func procStatFixture(pid uint32, name string, startTime uint64) []byte {
	return procStatFixtureText(
		strconv.FormatUint(uint64(pid), 10),
		name,
		strconv.FormatUint(startTime, 10),
	)
}

func procStatFixtureText(pid, name, startTime string) []byte {
	fields := make([]string, 0, 20)
	fields = append(fields, "S")
	for value := 1; value <= 18; value++ {
		fields = append(fields, strconv.Itoa(value))
	}
	fields = append(fields, startTime)
	return []byte(pid + " (" + name + ") " + strings.Join(fields, " ") + "\n")
}
