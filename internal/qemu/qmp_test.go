package qemu

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQMPHandshakeStatusEventAndPowerdown(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "qmp.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		encoder := json.NewEncoder(connection)
		decoder := json.NewDecoder(bufio.NewReader(connection))
		if err := encoder.Encode(map[string]any{"QMP": map[string]any{"version": map[string]any{"qemu": map[string]int{"major": 10, "minor": 2, "micro": 4}}, "capabilities": []string{}}}); err != nil {
			serverDone <- err
			return
		}
		for count := 0; count < 3; count++ {
			var request struct {
				Execute string `json:"execute"`
				ID      string `json:"id"`
			}
			if err := decoder.Decode(&request); err != nil {
				serverDone <- err
				return
			}
			if request.Execute == "query-status" {
				if err := encoder.Encode(map[string]any{"event": "RESUME", "timestamp": map[string]int64{"seconds": 1, "microseconds": 2}}); err != nil {
					serverDone <- err
					return
				}
				if err := encoder.Encode(map[string]any{"return": map[string]any{"status": "running", "running": true}, "id": request.ID}); err != nil {
					serverDone <- err
					return
				}
			} else if err := encoder.Encode(map[string]any{"return": map[string]any{}, "id": request.ID}); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := DialQMP(ctx, socket, DefaultQMPFrameLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	status, err := client.QueryStatus(ctx)
	if err != nil || !status.Running || status.Status != "running" {
		t.Fatalf("query status: result=%+v err=%v", status, err)
	}
	event, err := client.NextEvent(ctx)
	if err != nil || event.Name != "RESUME" {
		t.Fatalf("queued event: result=%+v err=%v", event, err)
	}
	if err := client.Powerdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestQMPRejectsOversizedGreeting(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "qmp.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_, _ = connection.Write([]byte(strings.Repeat("x", 8192) + "\n"))
			_ = connection.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := DialQMP(ctx, socket, 4096); err == nil {
		t.Fatal("oversized QMP greeting unexpectedly passed")
	}
}
