package guestvpn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	qBittorrentPreferencesURL = "http://127.0.0.1:8080/api/v2/app/preferences"
	maximumPreferencesBytes   = 64 << 10
	qBittorrentTimeout        = 5 * time.Second
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// LoopbackHTTPClient is the narrow authenticated client supplied by the
// downloader process owner. Implementations still pass the fixed-origin check
// in QBittorrentBindingProbe.
type LoopbackHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// QBittorrentBindingProbe uses the loopback-only Web API to verify the exact
// interface binding and disabled UPnP/NAT-PMP setting. Unknown preference
// fields are never materialized and the bounded response buffer is cleared.
type QBittorrentBindingProbe struct {
	client  httpDoer
	timeout time.Duration
}

func NewQBittorrentBindingProbe() *QBittorrentBindingProbe {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "127.0.0.1:8080" {
				return nil, errors.New("qBittorrent Web API target rejected")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
		},
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("qBittorrent redirect rejected")
		},
	}
	return &QBittorrentBindingProbe{client: client, timeout: qBittorrentTimeout}
}

func NewQBittorrentBindingProbeWithClient(client LoopbackHTTPClient) *QBittorrentBindingProbe {
	return &QBittorrentBindingProbe{client: client, timeout: qBittorrentTimeout}
}

func newQBittorrentBindingProbe(client httpDoer) *QBittorrentBindingProbe {
	return &QBittorrentBindingProbe{client: client, timeout: qBittorrentTimeout}
}

func (probe *QBittorrentBindingProbe) Bound(ctx context.Context) (bool, error) {
	if ctx == nil || probe == nil || isNilLike(probe.client) {
		return false, invalidRequest()
	}
	probeCtx, cancel := boundedContext(ctx, probe.effectiveTimeout())
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, qBittorrentPreferencesURL, nil)
	if err != nil {
		return false, errors.New("qBittorrent request failed")
	}
	request.Header.Set("Accept", "application/json")
	response, err := probe.client.Do(request)
	if err != nil {
		if probeCtx.Err() != nil {
			return false, probeCtx.Err()
		}
		return false, errors.New("qBittorrent request failed")
	}
	if response == nil || response.Body == nil {
		return false, errors.New("qBittorrent response missing")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, errors.New("qBittorrent response rejected")
	}
	value, err := io.ReadAll(io.LimitReader(response.Body, maximumPreferencesBytes+1))
	if err != nil || len(value) == 0 || len(value) > maximumPreferencesBytes {
		clear(value)
		return false, errors.New("qBittorrent response invalid")
	}
	defer clear(value)
	var preferences struct {
		CurrentNetworkInterface *string `json:"current_network_interface"`
		UPnP                    *bool   `json:"upnp"`
	}
	if err := json.Unmarshal(value, &preferences); err != nil || preferences.CurrentNetworkInterface == nil || preferences.UPnP == nil {
		return false, errors.New("qBittorrent preferences invalid")
	}
	return *preferences.CurrentNetworkInterface == TunnelInterface && !*preferences.UPnP, nil
}

func (probe *QBittorrentBindingProbe) effectiveTimeout() time.Duration {
	if probe.timeout <= 0 || probe.timeout > qBittorrentTimeout {
		return qBittorrentTimeout
	}
	return probe.timeout
}

var _ TorrentBindingProbe = (*QBittorrentBindingProbe)(nil)
