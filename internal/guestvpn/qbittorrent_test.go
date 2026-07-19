package guestvpn

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type httpDoerFunc func(*http.Request) (*http.Response, error)

func (function httpDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

func qbitResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestQBittorrentBindingRequiresExactInterfaceAndDisabledUPnP(t *testing.T) {
	for _, test := range []struct {
		name      string
		body      string
		want      bool
		wantError bool
	}{
		{name: "safe", body: `{"current_network_interface":"proton0","upnp":false,"web_ui_password":"sensitive-test-hash"}`, want: true},
		{name: "any interface", body: `{"current_network_interface":"","upnp":false}`},
		{name: "underlay", body: `{"current_network_interface":"eth0","upnp":false}`},
		{name: "upnp", body: `{"current_network_interface":"proton0","upnp":true}`},
		{name: "missing", body: `{"current_network_interface":"proton0"}`, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe := newQBittorrentBindingProbe(httpDoerFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method != http.MethodGet || request.URL.String() != qBittorrentPreferencesURL || request.Header.Get("Accept") != "application/json" {
					t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
				}
				return qbitResponse(http.StatusOK, test.body), nil
			}))
			bound, err := probe.Bound(context.Background())
			if (err != nil) != test.wantError || bound != test.want {
				t.Fatalf("Bound() = %v, %v; want %v", bound, err, test.want)
			}
		})
	}
}

func TestQBittorrentBindingBoundsTimeoutAndRedactsErrors(t *testing.T) {
	probe := newQBittorrentBindingProbe(httpDoerFunc(func(*http.Request) (*http.Response, error) {
		return qbitResponse(http.StatusOK, strings.Repeat("x", maximumPreferencesBytes+1)), nil
	}))
	if _, err := probe.Bound(context.Background()); err == nil {
		t.Fatal("oversized preferences passed")
	}
	probe.client = httpDoerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("sensitive qBittorrent response")
	})
	if _, err := probe.Bound(context.Background()); err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("unsafe qBittorrent error = %v", err)
	}
	probe.client = httpDoerFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	probe.timeout = 10 * time.Millisecond
	if _, err := probe.Bound(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("qBittorrent timeout = %v", err)
	}
}
