package qemu

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const DefaultQMPFrameLimit = 1 << 20

type QMPEvent struct {
	Name      string
	Timestamp time.Time
}

type QEMUStatus struct {
	Status  string `json:"status"`
	Running bool   `json:"running"`
}

type QMPClient struct {
	mu     sync.Mutex
	conn   *net.UnixConn
	reader *bufio.Reader
	limit  int
	nextID uint64
	events []QMPEvent
	closed bool
}

type qmpEnvelope struct {
	QMP       *qmpGreeting    `json:"QMP,omitempty"`
	Return    json.RawMessage `json:"return,omitempty"`
	Error     *qmpError       `json:"error,omitempty"`
	Event     string          `json:"event,omitempty"`
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
	} `json:"version"`
	Capabilities []string `json:"capabilities"`
}

type qmpError struct {
	Class string `json:"class"`
}

type qmpTimestamp struct {
	Seconds      int64 `json:"seconds"`
	Microseconds int64 `json:"microseconds"`
}

func DialQMP(ctx context.Context, socketPath string, frameLimit int) (*QMPClient, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return nil, errors.New("QMP socket path must be a clean absolute path")
	}
	if frameLimit <= 0 {
		frameLimit = DefaultQMPFrameLimit
	}
	if frameLimit < 4096 || frameLimit > 4<<20 {
		return nil, errors.New("QMP frame limit must be between 4 KiB and 4 MiB")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect QMP socket: %w", err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("QMP connection is not a Unix socket")
	}
	client := &QMPClient{conn: unixConnection, reader: bufio.NewReaderSize(unixConnection, frameLimit+1), limit: frameLimit}
	if err := client.handshake(ctx); err != nil {
		_ = client.Close()
		return nil, err
	}
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
	if err := json.Unmarshal(raw, &result); err != nil || result.Status == "" || len(result.Status) > 64 {
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
	if c.closed {
		return nil, errors.New("QMP client is closed")
	}
	switch name {
	case "qmp_capabilities", "query-status", "system_powerdown", "quit":
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
	if err := setWriteDeadline(c.conn, ctx); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(data); err != nil {
		return nil, fmt.Errorf("write QMP command: %w", err)
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
			if class == "" || len(class) > 64 {
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
	if err := setReadDeadline(c.conn, ctx); err != nil {
		return qmpEnvelope{}, err
	}
	line, err := c.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return qmpEnvelope{}, errors.New("QMP frame exceeds configured limit")
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			return qmpEnvelope{}, errors.New("QMP connection closed")
		}
		return qmpEnvelope{}, fmt.Errorf("read QMP frame: %w", err)
	}
	if len(line) > c.limit {
		return qmpEnvelope{}, errors.New("QMP frame exceeds configured limit")
	}
	var envelope qmpEnvelope
	if err := json.Unmarshal(line, &envelope); err != nil {
		return qmpEnvelope{}, errors.New("QMP frame is malformed JSON")
	}
	return envelope, nil
}

func (c *QMPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

func safeEvent(envelope qmpEnvelope) QMPEvent {
	name := envelope.Event
	if len(name) > 64 {
		name = "OVERSIZED_EVENT_NAME"
	}
	timestamp := time.Time{}
	if envelope.Timestamp != nil {
		timestamp = time.Unix(envelope.Timestamp.Seconds, envelope.Timestamp.Microseconds*1000).UTC()
	}
	return QMPEvent{Name: name, Timestamp: timestamp}
}

func setReadDeadline(conn *net.UnixConn, ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	return conn.SetReadDeadline(deadline)
}

func setWriteDeadline(conn *net.UnixConn, ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	return conn.SetWriteDeadline(deadline)
}
