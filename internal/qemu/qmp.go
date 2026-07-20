package qemu

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	DefaultQMPFrameLimit = 1 << 20
	qmpOperationLimit    = 5 * time.Second
	runtimeSocketMode    = 0o600
)

var qmpIdentifierPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

type QMPEvent struct {
	Name      string
	Timestamp time.Time
}

type QEMUStatus struct {
	Status  string `json:"status"`
	Running bool   `json:"running"`
}

type QMPClient struct {
	mu             sync.Mutex
	conn           *net.UnixConn
	reader         *bufio.Reader
	limit          int
	nextID         uint64
	events         []QMPEvent
	closed         atomic.Bool
	disconnect     chan struct{}
	monitorStop    chan struct{}
	disconnectOnce sync.Once
	monitorOnce    sync.Once
}

type qmpEnvelope struct {
	QMP       *qmpGreeting    `json:"QMP,omitempty"`
	Return    json.RawMessage `json:"return,omitempty"`
	Error     *qmpError       `json:"error,omitempty"`
	Event     string          `json:"event,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Timestamp *qmpTimestamp   `json:"timestamp,omitempty"`
	ID        string          `json:"id,omitempty"`
}

type qmpGreeting struct {
	Version struct {
		QEMU struct {
			Major int `json:"major"`
			Minor int `json:"minor"`
			Micro int `json:"micro"`
		} `json:"qemu"`
		Package string `json:"package"`
	} `json:"version"`
	Capabilities []string `json:"capabilities"`
}

type qmpError struct {
	Class string `json:"class"`
	Desc  string `json:"desc"`
}

type qmpTimestamp struct {
	Seconds      int64 `json:"seconds"`
	Microseconds int64 `json:"microseconds"`
}

func DialQMP(ctx context.Context, socketPath string, frameLimit int, expectedPID ...int) (*QMPClient, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return nil, errors.New("QMP socket path must be a clean absolute path")
	}
	if err := validateExistingUnixSocket(socketPath, runtimeSocketMode); err != nil {
		return nil, err
	}
	if frameLimit <= 0 {
		frameLimit = DefaultQMPFrameLimit
	}
	if frameLimit < 4096 || frameLimit > 4<<20 {
		return nil, errors.New("QMP frame limit must be between 4 KiB and 4 MiB")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("connect QMP socket: %w", ctx.Err())
		}
		return nil, errors.New("connect QMP socket failed")
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("QMP connection is not a Unix socket")
	}
	if len(expectedPID) > 1 || (len(expectedPID) == 1 && expectedPID[0] <= 1) {
		_ = connection.Close()
		return nil, errors.New("QMP expected peer PID is invalid")
	}
	if len(expectedPID) == 1 {
		if err := verifyQMPPeer(unixConnection, expectedPID[0]); err != nil {
			_ = connection.Close()
			return nil, err
		}
	}
	client := &QMPClient{
		conn: unixConnection, reader: bufio.NewReaderSize(unixConnection, frameLimit+1), limit: frameLimit,
		disconnect: make(chan struct{}), monitorStop: make(chan struct{}),
	}
	if err := client.handshake(ctx); err != nil {
		_ = client.Close()
		return nil, err
	}
	client.startDisconnectMonitor()
	return client, nil
}

func (c *QMPClient) handshake(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	envelope, err := c.readEnvelope(ctx)
	if err != nil {
		return fmt.Errorf("read QMP greeting: %w", err)
	}
	if envelope.QMP == nil || envelope.QMP.Version.QEMU.Major < 1 {
		return errors.New("QMP greeting is missing a valid QEMU version")
	}
	_, err = c.executeLocked(ctx, "qmp_capabilities", nil)
	if err != nil {
		return fmt.Errorf("negotiate QMP capabilities: %w", err)
	}
	return nil
}

func (c *QMPClient) QueryStatus(ctx context.Context) (QEMUStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, err := c.executeLocked(ctx, "query-status", nil)
	if err != nil {
		return QEMUStatus{}, err
	}
	var result QEMUStatus
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || !qmpIdentifierPattern.MatchString(result.Status) {
		return QEMUStatus{}, errors.New("QMP query-status returned an invalid response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return QEMUStatus{}, errors.New("QMP query-status returned an invalid response")
	}
	return result, nil
}

func (c *QMPClient) Powerdown(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.executeLocked(ctx, "system_powerdown", nil)
	return err
}

func (c *QMPClient) Quit(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.executeLocked(ctx, "quit", nil)
	return err
}

// AttachUSB adds only the one fixed exporter USB device shape. Callers cannot
// supply a driver, QEMU object identifier, bus name, or arbitrary arguments.
func (c *QMPClient) AttachUSB(ctx context.Context, bus, address uint8) error {
	if bus == 0 || address == 0 {
		return errors.New("QMP USB identity is invalid")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.executeLocked(ctx, "device_add", struct {
		Driver   string `json:"driver"`
		ID       string `json:"id"`
		Bus      string `json:"bus"`
		HostBus  int    `json:"hostbus"`
		HostAddr int    `json:"hostaddr"`
	}{Driver: "usb-host", ID: "private-vm-export-usb", Bus: "usb-controller.0", HostBus: int(bus), HostAddr: int(address)})
	return err
}

// DetachUSB removes only the exporter device ID created by AttachUSB.
func (c *QMPClient) DetachUSB(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.executeLocked(ctx, "device_del", struct {
		ID string `json:"id"`
	}{ID: "private-vm-export-usb"})
	return err
}

func (c *QMPClient) NextEvent(ctx context.Context) (QMPEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) > 0 {
		event := c.events[0]
		c.events = c.events[1:]
		return event, nil
	}
	envelope, err := c.readEnvelope(ctx)
	if err != nil {
		return QMPEvent{}, err
	}
	if envelope.Event != "" {
		return safeEvent(envelope), nil
	}
	return QMPEvent{}, errors.New("unexpected QMP response while waiting for an event")
}

func (c *QMPClient) executeLocked(ctx context.Context, name string, arguments any) (json.RawMessage, error) {
	if c.closed.Load() {
		return nil, errors.New("QMP client is closed")
	}
	switch name {
	case "qmp_capabilities", "query-status", "system_powerdown", "quit", "device_add", "device_del":
	default:
		return nil, errors.New("QMP command is not allowlisted")
	}
	c.nextID++
	id := "pvm-" + strconv.FormatUint(c.nextID, 10)
	request := struct {
		Execute   string `json:"execute"`
		Arguments any    `json:"arguments,omitempty"`
		ID        string `json:"id"`
	}{Execute: name, Arguments: arguments, ID: id}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, errors.New("encode allowlisted QMP command")
	}
	if len(data)+1 > c.limit {
		return nil, errors.New("QMP command exceeds frame limit")
	}
	data = append(data, '\n')
	stopDeadline, err := setWriteDeadline(c.conn, ctx)
	if err != nil {
		return nil, err
	}
	defer stopDeadline()
	if err := writeQMPFrame(c.conn, data); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("write QMP command failed")
	}
	for {
		envelope, err := c.readEnvelope(ctx)
		if err != nil {
			return nil, err
		}
		if envelope.Event != "" {
			if len(c.events) >= 64 {
				return nil, errors.New("QMP event queue exceeded its bound")
			}
			c.events = append(c.events, safeEvent(envelope))
			continue
		}
		if envelope.ID != id {
			return nil, errors.New("QMP response ID mismatch")
		}
		if envelope.Error != nil {
			class := envelope.Error.Class
			if !qmpIdentifierPattern.MatchString(class) {
				class = "unknown"
			}
			return nil, fmt.Errorf("QMP command rejected with class %s", class)
		}
		if envelope.Return == nil {
			return nil, errors.New("QMP response omitted both return and error")
		}
		return envelope.Return, nil
	}
}

func (c *QMPClient) readEnvelope(ctx context.Context) (qmpEnvelope, error) {
	stopDeadline, err := setReadDeadline(c.conn, ctx)
	if err != nil {
		return qmpEnvelope{}, err
	}
	defer stopDeadline()
	line, err := c.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return qmpEnvelope{}, errors.New("QMP frame exceeds configured limit")
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			return qmpEnvelope{}, errors.New("QMP connection closed")
		}
		if ctx.Err() != nil {
			return qmpEnvelope{}, ctx.Err()
		}
		if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
			return qmpEnvelope{}, errors.New("QMP read deadline exceeded")
		}
		return qmpEnvelope{}, errors.New("read QMP frame failed")
	}
	if len(line) > c.limit {
		return qmpEnvelope{}, errors.New("QMP frame exceeds configured limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var envelope qmpEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return qmpEnvelope{}, errors.New("QMP frame is malformed JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return qmpEnvelope{}, errors.New("QMP frame contains trailing JSON")
	}
	if err := validateQMPEnvelope(envelope); err != nil {
		return qmpEnvelope{}, err
	}
	return envelope, nil
}

func (c *QMPClient) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(c.monitorStop)
	return c.conn.Close()
}

func (c *QMPClient) Disconnected() <-chan struct{} { return c.disconnect }

func (c *QMPClient) startDisconnectMonitor() {
	c.monitorOnce.Do(func() {
		go func() {
			raw, err := c.conn.SyscallConn()
			if err != nil {
				c.signalDisconnect()
				return
			}
			monitorFD := -1
			if err := raw.Control(func(fd uintptr) {
				monitorFD, err = unix.Dup(int(fd))
			}); err != nil || monitorFD < 0 {
				c.signalDisconnect()
				return
			}
			defer unix.Close(monitorFD)
			for {
				select {
				case <-c.monitorStop:
					return
				default:
				}
				poll := []unix.PollFd{{Fd: int32(monitorFD), Events: unix.POLLERR | unix.POLLHUP | unix.POLLRDHUP}}
				if _, pollErr := unix.Poll(poll, 200); pollErr != nil || poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLRDHUP|unix.POLLNVAL) != 0 {
					c.signalDisconnect()
					return
				}
			}
		}()
	})
}

func (c *QMPClient) signalDisconnect() {
	c.disconnectOnce.Do(func() { close(c.disconnect) })
}

func verifyQMPPeer(connection *net.UnixConn, expectedPID int) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return errors.New("inspect QMP peer credentials failed")
	}
	var credentials *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || socketErr != nil || credentials == nil {
		return errors.New("inspect QMP peer credentials failed")
	}
	if credentials.Pid != int32(expectedPID) || credentials.Uid != uint32(os.Geteuid()) || credentials.Gid != uint32(os.Getegid()) {
		return errors.New("QMP peer process identity does not match the launched QEMU")
	}
	return nil
}

func safeEvent(envelope qmpEnvelope) QMPEvent {
	name := envelope.Event
	if !qmpIdentifierPattern.MatchString(name) {
		name = "INVALID_EVENT_NAME"
	}
	timestamp := time.Time{}
	if envelope.Timestamp != nil {
		timestamp = time.Unix(envelope.Timestamp.Seconds, envelope.Timestamp.Microseconds*1000).UTC()
	}
	return QMPEvent{Name: name, Timestamp: timestamp}
}

func setReadDeadline(conn *net.UnixConn, ctx context.Context) (func() bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	maximum := time.Now().Add(qmpOperationLimit)
	if !ok || maximum.Before(deadline) {
		deadline = maximum
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, errors.New("set QMP read bound failed")
	}
	return context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) }), nil
}

func setWriteDeadline(conn *net.UnixConn, ctx context.Context) (func() bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	maximum := time.Now().Add(qmpOperationLimit)
	if !ok || maximum.Before(deadline) {
		deadline = maximum
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return nil, errors.New("set QMP write bound failed")
	}
	return context.AfterFunc(ctx, func() { _ = conn.SetWriteDeadline(time.Now()) }), nil
}

func writeQMPFrame(connection *net.UnixConn, data []byte) error {
	for len(data) > 0 {
		written, err := connection.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func validateQMPEnvelope(envelope qmpEnvelope) error {
	categories := 0
	if envelope.QMP != nil {
		categories++
		if envelope.QMP.Version.QEMU.Major < 1 || len(envelope.QMP.Version.Package) > 256 || len(envelope.QMP.Capabilities) > 32 {
			return errors.New("QMP greeting has invalid bounded version data")
		}
		for _, capability := range envelope.QMP.Capabilities {
			if !qmpIdentifierPattern.MatchString(capability) {
				return errors.New("QMP greeting has an invalid capability")
			}
		}
	}
	if envelope.Event != "" {
		categories++
		if !qmpIdentifierPattern.MatchString(envelope.Event) {
			return errors.New("QMP event name is invalid")
		}
		if envelope.Timestamp != nil && (envelope.Timestamp.Microseconds < 0 || envelope.Timestamp.Microseconds > 999999) {
			return errors.New("QMP event timestamp is invalid")
		}
	}
	response := envelope.Return != nil || envelope.Error != nil
	if response {
		categories++
		if envelope.ID == "" || (envelope.Return != nil) == (envelope.Error != nil) {
			return errors.New("QMP response shape is invalid")
		}
		if envelope.Error != nil && (!qmpIdentifierPattern.MatchString(envelope.Error.Class) || len(envelope.Error.Desc) > 512) {
			return errors.New("QMP error shape is invalid")
		}
	}
	if categories != 1 {
		return errors.New("QMP envelope has an ambiguous or missing message type")
	}
	if envelope.QMP != nil && (envelope.ID != "" || envelope.Timestamp != nil || envelope.Data != nil) {
		return errors.New("QMP greeting contains response or event fields")
	}
	if envelope.Event != "" && envelope.ID != "" {
		return errors.New("QMP event contains a response ID")
	}
	if response && (envelope.Timestamp != nil || envelope.Data != nil) {
		return errors.New("QMP response contains event fields")
	}
	return nil
}

func validateExistingUnixSocket(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > maxUnixSocketPath {
		return errors.New("QMP socket path must be a bounded clean absolute path")
	}
	if err := validateSocketParent(filepath.Dir(path)); err != nil {
		return fmt.Errorf("QMP socket parent is unsafe: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.ErrNotExist
		}
		return errors.New("inspect QMP socket failed")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || info.Mode().Perm() != mode {
		return errors.New("QMP socket type, owner, group, or mode is unsafe")
	}
	return nil
}

func secureRuntimeSocket(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > maxUnixSocketPath {
		return errors.New("runtime socket path is unsafe")
	}
	if err := validateSocketParent(filepath.Dir(path)); err != nil {
		return fmt.Errorf("runtime socket parent is unsafe: %w", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSocket == 0 || beforeStat.Uid != uint32(os.Geteuid()) || beforeStat.Gid != uint32(os.Getegid()) {
		return errors.New("runtime socket type, owner, or group is unsafe")
	}
	if err := os.Chmod(path, runtimeSocketMode); err != nil {
		return errors.New("secure runtime socket mode failed")
	}
	after, err := os.Lstat(path)
	if err != nil {
		return errors.New("reinspect runtime socket failed")
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || after.Mode()&os.ModeSocket == 0 || after.Mode().Perm() != runtimeSocketMode || beforeStat.Dev != afterStat.Dev || beforeStat.Ino != afterStat.Ino {
		return errors.New("runtime socket identity changed while securing it")
	}
	return nil
}

func removeRuntimeSocket(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > maxUnixSocketPath {
		return errors.New("refusing to remove an unsafe runtime socket")
	}
	parentPath := filepath.Dir(path)
	if err := validateSocketParent(parentPath); err != nil {
		return errors.New("refusing to remove an unsafe runtime socket")
	}
	directory, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open runtime socket parent failed")
	}
	defer unix.Close(directory)
	var parentStat unix.Stat_t
	if err := unix.Fstat(directory, &parentStat); err != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Mode&0o777 != 0o700 || parentStat.Uid != uint32(os.Geteuid()) || parentStat.Gid != uint32(os.Getegid()) {
		return errors.New("runtime socket parent identity is unsafe")
	}
	base := filepath.Base(path)
	var socketStat unix.Stat_t
	err = unix.Fstatat(directory, base, &socketStat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errors.New("inspect runtime socket for removal failed")
	}
	if socketStat.Mode&unix.S_IFMT != unix.S_IFSOCK || socketStat.Mode&0o777 != uint32(runtimeSocketMode) || socketStat.Uid != uint32(os.Geteuid()) || socketStat.Gid != uint32(os.Getegid()) {
		return errors.New("refusing to remove an unsafe runtime socket")
	}
	if err := unix.Unlinkat(directory, base, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return errors.New("remove runtime socket failed")
	}
	if err := unix.Fstatat(directory, base, &socketStat, unix.AT_SYMLINK_NOFOLLOW); err == nil || !errors.Is(err, unix.ENOENT) {
		return errors.New("runtime socket remains after removal")
	}
	return nil
}
