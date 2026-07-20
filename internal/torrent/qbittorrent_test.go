package torrent

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type qbitRoundTrip func(*http.Request) (*http.Response, error)

func (roundTrip qbitRoundTrip) Do(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type qbitVerifier struct{ files []FileDigest }

func (verifier qbitVerifier) Verify(context.Context, Metadata) ([]FileDigest, error) {
	return append([]FileDigest(nil), verifier.files...), nil
}

func TestQBitBackendUsesOnlyLoopbackPausedQuarantineAPI(t *testing.T) {
	step := 0
	doer := qbitRoundTrip(func(request *http.Request) (*http.Response, error) {
		step++
		if request.URL.Scheme != "http" || request.URL.Host != "127.0.0.1:8080" || request.Header.Get("Referer") != qbitBaseURL || request.Header.Get("Origin") != qbitBaseURL {
			t.Fatalf("unsafe qBittorrent request: %s headers=%v", request.URL, request.Header)
		}
		var body []byte
		if request.Body != nil {
			var err error
			body, err = io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
		}
		defer clearBytes(body)
		response := ""
		switch step {
		case 1:
			if request.URL.Path != "/api/v2/torrents/info" {
				t.Fatalf("first path = %s", request.URL.Path)
			}
			response = "[]"
		case 2:
			if request.URL.Path != "/api/v2/torrents/add" || !bytes.Contains(body, []byte("name=\"stopped\"\r\n\r\ntrue")) ||
				!bytes.Contains(body, []byte(QuarantineDownloadDir)) || !bytes.Contains(body, []byte("name=\"urls\"")) {
				t.Fatalf("add request violated paused quarantine policy")
			}
		case 3:
			response = `[{"hash":"` + testHash + `","name":"fixture","state":"metaDL","save_path":"` + QuarantineDownloadDir + `","downloaded":0,"size":128}]`
		case 4:
			if request.URL.Path != "/api/v2/torrents/stop" || !bytes.Contains(body, []byte(testHash)) {
				t.Fatal("new torrent was not explicitly stopped")
			}
		default:
			t.Fatalf("unexpected request step %d: %s", step, request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header), Request: request}, nil
	})
	backend, err := NewQBitBackend(doer, qbitVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	input := mustInput(t)
	defer input.Destroy()
	handle, err := backend.AddPaused(t.Context(), input)
	if err != nil || !handle.valid() || step != 4 {
		t.Fatalf("AddPaused handle=%v err=%v step=%d", handle, err, step)
	}
}

func TestQBitBackendBoundsResponsesAndRejectsOtherSavePath(t *testing.T) {
	for name, response := range map[string]string{
		"other path": `[{"hash":"` + testHash + `","name":"fixture","state":"stoppedDL","save_path":"/tmp/escape","downloaded":0,"size":1}]`,
		"too many":   `[{"hash":"` + testHash + `"},{"hash":"` + testHash + `"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			backend, err := NewQBitBackend(qbitRoundTrip(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(response)), Request: request}, nil
			}), qbitVerifier{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := backend.list(t.Context()); err == nil || strings.Contains(err.Error(), "/tmp/escape") || strings.Contains(err.Error(), testHash) {
				t.Fatalf("unsafe list error = %v", err)
			}
		})
	}
}
