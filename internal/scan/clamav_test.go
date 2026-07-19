package scan

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseClamdResponseFailClosed(t *testing.T) {
	tests := []struct {
		response string
		code     string
		clean    bool
		wantErr  bool
	}{
		{"stream: OK", "CLAMAV_CLEAN", true, false},
		{"stream: Eicar-Signature FOUND", "MALWARE_DETECTED", false, false},
		{"stream: Heuristics.Encrypted.Zip FOUND", "MALWARE_DETECTED", false, false},
		{"stream: encrypted archive ERROR", "ARCHIVE_ENCRYPTED", false, false},
		{"stream: scan size limit exceeded ERROR", "SCAN_LIMIT_REACHED", false, false},
		{"stream: timeout ERROR", "SCAN_TIMEOUT", false, false},
		{"stream: can't read ERROR", "SCAN_FILE_SKIPPED", false, false},
		{"stream: internal failure ERROR", "SCAN_ERROR", false, false},
		{"stream: MAYBE", "SCAN_ERROR", false, true},
		{"filename: OK", "SCAN_ERROR", false, true},
	}
	for _, test := range tests {
		t.Run(test.response, func(t *testing.T) {
			result, err := ParseClamdResponse([]byte(test.response))
			if test.wantErr {
				if ErrorCode(err) != test.code {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || result.Clean != test.clean || result.Finding.Code != test.code || !result.Finding.valid() {
				t.Fatalf("result = %+v, error = %v", result, err)
			}
		})
	}
}

func TestClamdClientStreamsExactBoundedInput(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		command := make([]byte, len("zINSTREAM\x00"))
		if _, err := io.ReadFull(server, command); err != nil {
			done <- err
			return
		}
		if string(command) != "zINSTREAM\x00" {
			done <- errors.New("wrong command")
			return
		}
		var received bytes.Buffer
		for {
			var header [4]byte
			if _, err := io.ReadFull(server, header[:]); err != nil {
				done <- err
				return
			}
			size := binary.BigEndian.Uint32(header[:])
			if size == 0 {
				break
			}
			if size > 4096 {
				done <- errors.New("chunk exceeded bound")
				return
			}
			if _, err := io.CopyN(&received, server, int64(size)); err != nil {
				done <- err
				return
			}
		}
		if received.String() != "test fixture" {
			done <- errors.New("wrong body")
			return
		}
		_, err := server.Write([]byte("stream: OK\x00"))
		done <- err
	}()
	clamd := ClamdClient{
		Dial:          func(context.Context) (net.Conn, error) { return client, nil },
		MaxInputBytes: 64, ChunkBytes: 4096, IdleTimeout: time.Second,
	}
	result, err := clamd.Scan(t.Context(), strings.NewReader("test fixture"), uint64(len("test fixture")))
	if err != nil || !result.Clean {
		t.Fatalf("result = %+v, error = %v", result, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestClamdClientRejectsShortChangedAndTimeout(t *testing.T) {
	drainingDialer := func(context.Context) (net.Conn, error) {
		left, right := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, right)
			_ = right.Close()
		}()
		return left, nil
	}
	client := ClamdClient{Dial: drainingDialer, MaxInputBytes: 32, ChunkBytes: 4096, IdleTimeout: time.Second}
	if _, err := client.Scan(t.Context(), strings.NewReader("short"), 6); ErrorCode(err) != "SCAN_FILE_SKIPPED" {
		t.Fatalf("short input error = %v", err)
	}

	client.Dial = drainingDialer
	if _, err := client.Scan(t.Context(), strings.NewReader("extra"), 4); ErrorCode(err) != "SCAN_FILE_CHANGED" {
		t.Fatalf("changed input error = %v", err)
	}

	server2, connection2 := net.Pipe()
	defer server2.Close()
	client.Dial = func(context.Context) (net.Conn, error) { return connection2, nil }
	client.IdleTimeout = 2 * time.Millisecond
	if _, err := client.Scan(t.Context(), strings.NewReader("x"), 1); ErrorCode(err) != "SCAN_TIMEOUT" {
		t.Fatalf("timeout error = %v", err)
	}
}

type scannerFunc func(context.Context, io.Reader, uint64) (ClamResult, error)

func (f scannerFunc) Scan(ctx context.Context, reader io.Reader, size uint64) (ClamResult, error) {
	return f(ctx, reader, size)
}

func TestScanInventorySuccessFailureAndCleanup(t *testing.T) {
	inventory := Inventory{Entries: []InventoryEntry{{RelativePath: "one", SizeBytes: 1}, {RelativePath: "two", SizeBytes: 1}}, TotalBytes: 2}
	closed := 0
	opener := func(_ context.Context, entry InventoryEntry) (io.ReadCloser, error) {
		return &trackedReadCloser{Reader: strings.NewReader("x"), closed: &closed}, nil
	}
	summary, err := ScanInventory(t.Context(), inventory, opener, scannerFunc(func(context.Context, io.Reader, uint64) (ClamResult, error) {
		return ClamResult{Clean: true, Finding: Finding{Code: "CLAMAV_CLEAN", Severity: SeverityInfo, Detail: "complete"}}, nil
	}))
	if err != nil || !summary.Complete || summary.ScannedFiles != 2 || closed != 2 {
		t.Fatalf("summary = %+v, closed = %d, error = %v", summary, closed, err)
	}

	closed = 0
	_, err = ScanInventory(t.Context(), inventory, opener, scannerFunc(func(context.Context, io.Reader, uint64) (ClamResult, error) {
		return ClamResult{}, scanError("SCAN_ERROR", "failed", "retry", nil)
	}))
	if ErrorCode(err) != "SCAN_ERROR" || closed != 1 {
		t.Fatalf("error = %v, closed = %d", err, closed)
	}
}

type trackedReadCloser struct {
	io.Reader
	closed *int
}

func (r *trackedReadCloser) Close() error {
	*r.closed++
	return nil
}

func FuzzParseClamdResponse(f *testing.F) {
	for _, seed := range []string{"stream: OK", "stream: Eicar FOUND", "stream: timeout ERROR", "", "stream: OK\x00trailing"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > DefaultClamdResponseBytes+1 {
			return
		}
		result, err := ParseClamdResponse(input)
		if err == nil && !result.Finding.valid() {
			t.Fatal("parser returned an invalid finding")
		}
	})
}
