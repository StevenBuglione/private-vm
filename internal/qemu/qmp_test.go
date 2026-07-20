package qemu

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func FuzzQMPEnvelope(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"QMP":{"version":{"qemu":{"major":10,"minor":2,"micro":4},"package":""},"capabilities":[]}}`),
		[]byte(`{"return":{},"id":"pvm-1"}`),
		[]byte(`{"event":"STOP","timestamp":{"seconds":1,"microseconds":0}}`),
		[]byte(`{"error":{"class":"GenericError","desc":"safe"},"id":"pvm-2"}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var envelope qmpEnvelope
		if err := decoder.Decode(&envelope); err != nil {
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return
		}
		_ = validateQMPEnvelope(envelope)
	})
}

func TestQMPHandshakeStatusEventAndPowerdown(t *testing.T) {
	socket := filepath.Join(privateTestDir(t), "qmp.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, runtimeSocketMode); err != nil {
		t.Fatal(err)
	}
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

func TestQMPExporterUSBHotplugUsesFixedTypedShape(t *testing.T) {
	socket := filepath.Join(privateTestDir(t), "qmp.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, runtimeSocketMode); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		encoder := json.NewEncoder(connection)
		decoder := json.NewDecoder(connection)
		if err := encoder.Encode(map[string]any{"QMP": map[string]any{"version": map[string]any{"qemu": map[string]int{"major": 10, "minor": 2, "micro": 4}, "package": ""}, "capabilities": []string{}}}); err != nil {
			serverDone <- err
			return
		}
		for index := 0; index < 3; index++ {
			var request struct {
				Execute   string `json:"execute"`
				Arguments struct {
					Driver   string `json:"driver"`
					ID       string `json:"id"`
					Bus      string `json:"bus"`
					HostBus  int    `json:"hostbus"`
					HostAddr int    `json:"hostaddr"`
				} `json:"arguments"`
				ID string `json:"id"`
			}
			if err := decoder.Decode(&request); err != nil {
				serverDone <- err
				return
			}
			switch index {
			case 0:
				if request.Execute != "qmp_capabilities" {
					serverDone <- errors.New("missing QMP capability negotiation")
					return
				}
			case 1:
				if request.Execute != "device_add" || request.Arguments.Driver != "usb-host" || request.Arguments.ID != "private-vm-export-usb" || request.Arguments.Bus != "usb-controller.0" || request.Arguments.HostBus != 7 || request.Arguments.HostAddr != 9 {
					serverDone <- errors.New("USB attach command shape changed")
					return
				}
			case 2:
				if request.Execute != "device_del" || request.Arguments.ID != "private-vm-export-usb" || request.Arguments.Driver != "" || request.Arguments.Bus != "" || request.Arguments.HostBus != 0 || request.Arguments.HostAddr != 0 {
					serverDone <- errors.New("USB detach command shape changed")
					return
				}
			}
			if err := encoder.Encode(map[string]any{"return": map[string]any{}, "id": request.ID}); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := DialQMP(ctx, socket, DefaultQMPFrameLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.AttachUSB(ctx, 7, 9); err != nil {
		t.Fatal(err)
	}
	if err := client.DetachUSB(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestQMPRejectsOversizedGreeting(t *testing.T) {
	socket := filepath.Join(privateTestDir(t), "qmp.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, runtimeSocketMode); err != nil {
		t.Fatal(err)
	}
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

func TestQMPRejectsUnsafeSocketMode(t *testing.T) {
	socket := filepath.Join(privateTestDir(t), "qmp.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := DialQMP(context.Background(), socket, DefaultQMPFrameLimit); err == nil {
		t.Fatal("unsafe QMP socket mode unexpectedly passed")
	}
}

func TestQMPRejectsPeerPIDMismatch(t *testing.T) {
	socket := filepath.Join(privateTestDir(t), "qmp.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, runtimeSocketMode); err != nil {
		t.Fatal(err)
	}
	go serveQMP(t, listener, func(net.Conn, *json.Decoder, *json.Encoder) {})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := DialQMP(ctx, socket, DefaultQMPFrameLimit, os.Getpid()+1); err == nil {
		t.Fatal("QMP connection from the wrong peer PID unexpectedly passed")
	}
}

func TestQMPDisconnectIsBoundedAndRedacted(t *testing.T) {
	socket := filepath.Join(privateTestDir(t), "qmp-secret-name.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, runtimeSocketMode); err != nil {
		t.Fatal(err)
	}
	go serveQMP(t, listener, func(connection net.Conn, decoder *json.Decoder, encoder *json.Encoder) {
		var request qmpTestRequest
		if err := decoder.Decode(&request); err != nil {
			return
		}
		_ = encoder.Encode(map[string]any{"return": map[string]any{}, "id": request.ID})
		if err := decoder.Decode(&request); err != nil {
			return
		}
		_ = connection.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := DialQMP(ctx, socket, DefaultQMPFrameLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	started := time.Now()
	_, err = client.QueryStatus(ctx)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("disconnect was not a bounded failure: %v", err)
	}
	if strings.Contains(err.Error(), "qmp-secret-name") {
		t.Fatalf("QMP error exposed socket path: %v", err)
	}
}

func TestQMPCancellationInterruptsBlockedRead(t *testing.T) {
	socket := filepath.Join(privateTestDir(t), "qmp.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, runtimeSocketMode); err != nil {
		t.Fatal(err)
	}
	requestSeen := make(chan struct{})
	go serveQMP(t, listener, func(_ net.Conn, decoder *json.Decoder, encoder *json.Encoder) {
		var request qmpTestRequest
		if err := decoder.Decode(&request); err != nil {
			return
		}
		_ = encoder.Encode(map[string]any{"return": map[string]any{}, "id": request.ID})
		if err := decoder.Decode(&request); err != nil {
			return
		}
		close(requestSeen)
		<-time.After(time.Second)
	})
	client, err := DialQMP(context.Background(), socket, DefaultQMPFrameLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, queryErr := client.QueryStatus(ctx)
		result <- queryErr
	}()
	<-requestSeen
	started := time.Now()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("canceled QMP read was not interrupted: %v", err)
	}
}

func TestQMPRejectsUnknownGreetingFields(t *testing.T) {
	socket := filepath.Join(privateTestDir(t), "qmp.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, runtimeSocketMode); err != nil {
		t.Fatal(err)
	}
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_, _ = connection.Write([]byte(`{"QMP":{"version":{"qemu":{"major":10,"minor":2,"micro":4},"package":""},"capabilities":[]},"unexpected":true}` + "\n"))
			_ = connection.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := DialQMP(ctx, socket, DefaultQMPFrameLimit); err == nil {
		t.Fatal("unknown QMP greeting field unexpectedly passed")
	}
}

type qmpTestRequest struct {
	Execute string `json:"execute"`
	ID      string `json:"id"`
}

func serveQMP(t *testing.T, listener net.Listener, behavior func(net.Conn, *json.Decoder, *json.Encoder)) {
	t.Helper()
	connection, err := listener.Accept()
	if err != nil {
		return
	}
	defer connection.Close()
	encoder := json.NewEncoder(connection)
	decoder := json.NewDecoder(bufio.NewReader(connection))
	if err := encoder.Encode(map[string]any{"QMP": map[string]any{"version": map[string]any{"qemu": map[string]int{"major": 10, "minor": 2, "micro": 4}, "package": ""}, "capabilities": []string{}}}); err != nil {
		return
	}
	behavior(connection, decoder, encoder)
}
