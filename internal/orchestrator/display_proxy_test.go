package orchestrator

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const displayTestSessionID = "pvm-dddddddddddddddddddddddddddddddd"

func TestDisplayProxyRelaysOnlyThroughOwnedUnixSocketAndCleansUp(t *testing.T) {
	runtimeRoot := shortDisplayRoot(t)
	if err := os.Chmod(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	sourceDirectory := filepath.Join(runtimeRoot, displayTestSessionID, "spice")
	if err := os.MkdirAll(sourceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(runtimeRoot, displayTestSessionID), 0o700); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(sourceDirectory, "spice.sock")
	source, err := net.ListenUnix("unix", &net.UnixAddr{Name: sourcePath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	source.SetUnlinkOnClose(false)
	if err := os.Chmod(sourcePath, 0o600); err != nil {
		t.Fatal(err)
	}
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		connection, acceptErr := source.AcceptUnix()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()

	proxy, err := startDisplayProxy(runtimeRoot, displayTestSessionID, uint32(os.Geteuid()), sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	target, err := DisplaySocketPath(runtimeRoot, displayTestSessionID)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: target, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("display-frame")); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("display-frame"))
	if _, err := io.ReadFull(client, buffer); err != nil || string(buffer) != "display-frame" {
		t.Fatalf("relay = %q, %v", buffer, err)
	}
	second, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: target, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("second display client was not rejected")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("second display client hung until its deadline")
	}
	_ = second.Close()
	_ = client.Close()
	if err := proxy.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := proxy.Audit(); err != nil {
		t.Fatal(err)
	}
	_ = source.Close()
	select {
	case <-echoDone:
	case <-time.After(time.Second):
		t.Fatal("source relay did not stop")
	}
}

func TestDisplayProxyRefusesToRemoveReplacedSocket(t *testing.T) {
	runtimeRoot := shortDisplayRoot(t)
	sourceDirectory := filepath.Join(runtimeRoot, displayTestSessionID, "spice")
	if err := os.MkdirAll(sourceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(runtimeRoot, displayTestSessionID), 0o700); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(sourceDirectory, "spice.sock")
	source, err := net.ListenUnix("unix", &net.UnixAddr{Name: sourcePath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	source.SetUnlinkOnClose(false)
	if err := os.Chmod(sourcePath, 0o600); err != nil {
		t.Fatal(err)
	}
	proxy, err := startDisplayProxy(runtimeRoot, displayTestSessionID, uint32(os.Geteuid()), sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := DisplaySocketPath(runtimeRoot, displayTestSessionID)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := proxy.Stop(); err == nil {
		t.Fatal("replacement was accepted during cleanup")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("replacement changed = %q, %v", data, err)
	}
}

func shortDisplayRoot(t *testing.T) string {
	t.Helper()
	path, err := os.MkdirTemp("/tmp", "pvm-display-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })
	return path
}
