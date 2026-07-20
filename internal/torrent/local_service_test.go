package torrent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/guestvpn"
)

type fakeLocalManager struct {
	starts, stops int
	startErr      error
	stopErr       error
}

func (manager *fakeLocalManager) Start(context.Context) error {
	manager.starts++
	return manager.startErr
}
func (manager *fakeLocalManager) Stop(context.Context) error {
	manager.stops++
	return manager.stopErr
}

type localDoer func(*http.Request) (*http.Response, error)

func (doer localDoer) Do(request *http.Request) (*http.Response, error) { return doer(request) }

func TestLocalQBittorrentServiceUsesPerBootHashAndAuthenticatedLoopback(t *testing.T) {
	manager := &fakeLocalManager{}
	fixture := bytes.Repeat([]byte{0x5a}, qbitCredentialBytes+qbitSaltBytes)
	encodedPassword := base64RawURL(bytes.Repeat([]byte{0x5a}, qbitCredentialBytes))
	var config []byte
	doer := localDoer(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == qbitLoginURL {
			body, _ := io.ReadAll(request.Body)
			defer clearBytes(body)
			if !bytes.Contains(body, []byte("username="+qbitUsername+"&password=")) || !bytes.Contains(body, encodedPassword) {
				t.Fatal("login did not use the generated per-boot credential")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("Ok.")), Header: http.Header{"Set-Cookie": {"SID=abcdefghijklmnop12345678; path=/"}}}, nil
		}
		if request.Header.Get("Cookie") != "SID=abcdefghijklmnop12345678" || request.URL.Host != "127.0.0.1:8080" {
			t.Fatal("authenticated request did not remain on fixed loopback")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"current_network_interface":"proton0","upnp":false}`)), Header: make(http.Header)}, nil
	})
	service, err := newLocalQBittorrentService(manager, doer, "/tmp/test-qbit/config/qBittorrent/qBittorrent.conf", 1000, 100, bytes.NewReader(fixture), func(_ string, value []byte, _, _ int) error {
		config = append([]byte(nil), value...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clearBytes(config) })
	if bytes.Contains(config, encodedPassword) || !bytes.Contains(config, []byte("WebUI\\Password_PBKDF2=\"@ByteArray(")) ||
		!bytes.Contains(config, []byte("WebUI\\LocalHostAuth=true")) || !bytes.Contains(config, []byte("WebUI\\AuthSubnetWhitelistEnabled=false")) ||
		!bytes.Contains(config, []byte("Session\\InterfaceName=proton0")) {
		t.Fatal("volatile qBittorrent config retained plaintext or omitted fixed policy")
	}
	if err := service.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	probe := guestvpn.NewQBittorrentBindingProbeWithClient(service)
	if ok, err := probe.Bound(t.Context()); err != nil || !ok {
		t.Fatalf("binding probe ok=%t err=%v", ok, err)
	}
	if err := service.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := service.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if manager.starts != 1 || manager.stops != 1 {
		t.Fatalf("service manager starts=%d stops=%d", manager.starts, manager.stops)
	}
	service.password.Destroy()
}

func TestLocalQBittorrentServiceCancellationStopsPartialStart(t *testing.T) {
	manager := &fakeLocalManager{}
	service, err := newLocalQBittorrentService(manager, localDoer(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("fixture unavailable")
	}), "/tmp/test-qbit/config/qBittorrent/qBittorrent.conf", 1000, 100, bytes.NewReader(bytes.Repeat([]byte{1}, qbitCredentialBytes+qbitSaltBytes)), func(string, []byte, int, int) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled start = %v", err)
	}
	if manager.starts != 1 || manager.stops != 1 || service.started {
		t.Fatalf("partial start cleanup starts=%d stops=%d active=%t", manager.starts, manager.stops, service.started)
	}
	service.password.Destroy()
}

func TestLocalQBittorrentServiceRetainsFailedStopForRetry(t *testing.T) {
	manager := &fakeLocalManager{stopErr: errors.New("fixture stop failure")}
	service, err := newLocalQBittorrentService(manager, localDoer(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("fixture unavailable")
	}), "/tmp/test-qbit/config/qBittorrent/qBittorrent.conf", 1000, 100, bytes.NewReader(bytes.Repeat([]byte{2}, qbitCredentialBytes+qbitSaltBytes)), func(string, []byte, int, int) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.Start(ctx); !errors.Is(err, context.Canceled) || !service.started {
		t.Fatalf("failed partial-stop ownership: err=%v active=%t", err, service.started)
	}
	manager.stopErr = nil
	if err := service.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if service.started || manager.stops != 2 {
		t.Fatalf("stop retry state active=%t stops=%d", service.started, manager.stops)
	}
}

func TestLocalQBittorrentServiceCleansAmbiguousStartFailure(t *testing.T) {
	manager := &fakeLocalManager{startErr: context.DeadlineExceeded}
	service, err := newLocalQBittorrentService(manager, localDoer(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("must not login")
	}), "/tmp/test-qbit/config/qBittorrent/qBittorrent.conf", 1000, 100, bytes.NewReader(bytes.Repeat([]byte{3}, qbitCredentialBytes+qbitSaltBytes)), func(string, []byte, int, int) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ambiguous start = %v", err)
	}
	if service.started || manager.starts != 1 || manager.stops != 1 {
		t.Fatalf("ambiguous start cleanup active=%t starts=%d stops=%d", service.started, manager.starts, manager.stops)
	}
	if err := service.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestPBKDF2SHA512MatchesPinnedQBittorrentContract(t *testing.T) {
	derived := pbkdf2SHA512([]byte("password"), []byte("salt"), 2)
	defer clearBytes(derived)
	want := "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"
	if len(derived) != qbitPasswordKeyBytes || hex.EncodeToString(derived) != want {
		t.Fatal("PBKDF2-HMAC-SHA-512 compatibility vector mismatch")
	}
}

func base64RawURL(value []byte) []byte {
	result := make([]byte, base64.RawURLEncoding.EncodedLen(len(value)))
	base64.RawURLEncoding.Encode(result, value)
	return result
}
