package torrent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	qbitBaseURL          = "http://127.0.0.1:8080"
	maximumQBitResponse  = 2 << 20
	maximumQBitOperation = 30 * time.Second
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type CompletedVerifier interface {
	Verify(context.Context, Metadata) ([]FileDigest, error)
}

// QBitBackend is restricted to the guest-local qBittorrent v2 API. The base
// URL, quarantine path, Referer, methods and request fields are package-owned.
// It cannot target a remote Web UI or choose another save directory.
type QBitBackend struct {
	doer     HTTPDoer
	verifier CompletedVerifier
}

func NewQBitBackend(doer HTTPDoer, verifier CompletedVerifier) (*QBitBackend, error) {
	if nilLike(doer) || nilLike(verifier) {
		return nil, invalidRequest()
	}
	return &QBitBackend{doer: doer, verifier: verifier}, nil
}

func (backend *QBitBackend) AddPaused(ctx context.Context, input *Input) (Handle, error) {
	if backend == nil || ctx == nil || input == nil {
		return Handle{}, invalidRequest()
	}
	before, err := backend.list(ctx)
	if err != nil || len(before) != 0 {
		return Handle{}, invalidRequest()
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	writeErr := input.WithReader(ctx, func(_ context.Context, reader io.Reader) error {
		var part io.Writer
		var err error
		switch input.Kind() {
		case InputMagnet:
			part, err = writer.CreateFormField("urls")
		case InputMetainfo:
			part, err = writer.CreateFormFile("torrents", "input.torrent")
		default:
			return invalidRequest()
		}
		if err != nil {
			return err
		}
		_, err = io.Copy(part, io.LimitReader(reader, int64(inputMaximum(input.Kind())+1)))
		return err
	})
	if writeErr == nil {
		for key, value := range map[string]string{
			"savepath": QuarantineDownloadDir, "stopped": "true", "autoTMM": "false",
			"sequentialDownload": "false", "firstLastPiecePrio": "false", "ratioLimit": "0", "seedingTimeLimit": "0",
		} {
			writeErr = writer.WriteField(key, value)
			if writeErr != nil {
				break
			}
		}
	}
	if closeErr := writer.Close(); writeErr == nil {
		writeErr = closeErr
	}
	defer clearBytes(body.Bytes())
	if writeErr != nil || body.Len() > MaximumMetainfoBytes+(64<<10) {
		return Handle{}, invalidInput()
	}
	response, err := backend.request(ctx, http.MethodPost, "/api/v2/torrents/add", writer.FormDataContentType(), bytes.NewReader(body.Bytes()), 16)
	clearBytes(response)
	if err != nil {
		return Handle{}, invalidInput()
	}
	after, err := backend.list(ctx)
	if err != nil || len(after) != 1 {
		return Handle{}, invalidInput()
	}
	handle, err := NewHandle(after[0].Hash)
	if err != nil {
		return Handle{}, invalidInput()
	}
	if err := backend.Pause(ctx, handle); err != nil {
		return Handle{}, err
	}
	return handle, nil
}

func (backend *QBitBackend) Metadata(ctx context.Context, handle Handle) (RawMetadata, error) {
	if !handle.valid() {
		return RawMetadata{}, invalidRequest()
	}
	items, err := backend.list(ctx)
	if err != nil || len(items) != 1 || items[0].Hash != handle.value {
		return RawMetadata{}, errors.New("bounded qBittorrent metadata query failed")
	}
	item := items[0]
	if item.Downloaded < 0 {
		return RawMetadata{}, errors.New("bounded qBittorrent metadata response failed")
	}
	if item.State == "metaDL" || item.State == "checkingDL" || item.Name == "" {
		return RawMetadata{Available: false, PayloadRead: uint64(item.Downloaded)}, nil
	}
	path := "/api/v2/torrents/files?hash=" + url.QueryEscape(handle.value)
	raw, err := backend.request(ctx, http.MethodGet, path, "", nil, maximumQBitResponse)
	if err != nil {
		return RawMetadata{}, err
	}
	var files []struct {
		Index uint32 `json:"index"`
		Name  string `json:"name"`
		Size  int64  `json:"size"`
	}
	if err := decodeStrictJSON(raw, &files); err != nil || len(files) == 0 || len(files) > MaximumFiles {
		return RawMetadata{}, errors.New("bounded qBittorrent metadata response failed")
	}
	result := RawMetadata{Available: true, PayloadRead: uint64(item.Downloaded), DisplayName: item.Name, Files: make([]RawFile, len(files))}
	for index, file := range files {
		if file.Index != uint32(index) || file.Size <= 0 {
			return RawMetadata{}, errors.New("bounded qBittorrent metadata response failed")
		}
		result.Files[index] = RawFile{Index: file.Index, Path: file.Name, Size: uint64(file.Size)}
	}
	return result, nil
}

func (backend *QBitBackend) SetSelection(ctx context.Context, handle Handle, selected []uint32, fileCount uint32) error {
	if !handle.valid() || fileCount == 0 || fileCount > MaximumFiles || len(selected) > int(fileCount) {
		return invalidRequest()
	}
	all := make([]string, fileCount)
	for index := range all {
		all[index] = strconv.Itoa(index)
	}
	if err := backend.form(ctx, "/api/v2/torrents/filePrio", url.Values{"hash": {handle.value}, "id": {strings.Join(all, "|")}, "priority": {"0"}}); err != nil {
		return err
	}
	if len(selected) == 0 {
		return nil
	}
	ids := make([]string, len(selected))
	seen := make(map[uint32]struct{}, len(selected))
	for index, current := range selected {
		if current >= fileCount {
			return invalidRequest()
		}
		if _, exists := seen[current]; exists {
			return invalidRequest()
		}
		seen[current] = struct{}{}
		ids[index] = strconv.FormatUint(uint64(current), 10)
	}
	return backend.form(ctx, "/api/v2/torrents/filePrio", url.Values{"hash": {handle.value}, "id": {strings.Join(ids, "|")}, "priority": {"1"}})
}

func (backend *QBitBackend) Start(ctx context.Context, handle Handle) error {
	return backend.handleForm(ctx, "/api/v2/torrents/start", handle)
}

func (backend *QBitBackend) Pause(ctx context.Context, handle Handle) error {
	return backend.handleForm(ctx, "/api/v2/torrents/stop", handle)
}

func (backend *QBitBackend) Status(ctx context.Context, handle Handle) (ClientStatus, error) {
	items, err := backend.list(ctx)
	if err != nil || len(items) != 1 || !handle.valid() || items[0].Hash != handle.value || items[0].Downloaded < 0 || items[0].Size < 0 {
		return ClientStatus{}, errors.New("bounded qBittorrent status query failed")
	}
	item := items[0]
	state := ClientRunning
	switch item.State {
	case "stoppedDL", "pausedDL", "stalledDL":
		state = ClientPaused
	case "stoppedUP", "pausedUP", "uploading", "stalledUP":
		state = ClientComplete
	case "error", "missingFiles", "unknown":
		state = ClientError
	case "metaDL":
		state = ClientMetadata
	}
	return ClientStatus{State: state, CompletedBytes: uint64(item.Downloaded), TotalBytes: uint64(item.Size)}, nil
}

func (backend *QBitBackend) VerifyCompleted(ctx context.Context, handle Handle, metadata Metadata) ([]FileDigest, error) {
	status, err := backend.Status(ctx, handle)
	if err != nil || status.State != ClientComplete || status.CompletedBytes != metadata.SelectedSizeBytes || status.TotalBytes != metadata.SelectedSizeBytes {
		return nil, sealFailed()
	}
	return backend.verifier.Verify(ctx, metadata)
}

func (backend *QBitBackend) Shutdown(ctx context.Context) error {
	response, err := backend.request(ctx, http.MethodPost, "/api/v2/app/shutdown", "application/x-www-form-urlencoded", strings.NewReader(""), 16)
	clearBytes(response)
	return err
}

type qbitInfo struct {
	Hash       string `json:"hash"`
	Name       string `json:"name"`
	State      string `json:"state"`
	SavePath   string `json:"save_path"`
	Downloaded int64  `json:"downloaded"`
	Size       int64  `json:"size"`
}

func (backend *QBitBackend) list(ctx context.Context) ([]qbitInfo, error) {
	raw, err := backend.request(ctx, http.MethodGet, "/api/v2/torrents/info", "", nil, maximumQBitResponse)
	if err != nil {
		return nil, err
	}
	var result []qbitInfo
	if err := decodeStrictJSON(raw, &result); err != nil || len(result) > 1 {
		return nil, errors.New("bounded qBittorrent list response failed")
	}
	for _, item := range result {
		if item.SavePath != "" && item.SavePath != QuarantineDownloadDir {
			return nil, errors.New("qBittorrent save path left quarantine")
		}
	}
	return result, nil
}

func (backend *QBitBackend) handleForm(ctx context.Context, endpoint string, handle Handle) error {
	if !handle.valid() {
		return invalidRequest()
	}
	return backend.form(ctx, endpoint, url.Values{"hashes": {handle.value}})
}

func (backend *QBitBackend) form(ctx context.Context, endpoint string, values url.Values) error {
	encoded := []byte(values.Encode())
	defer clearBytes(encoded)
	response, err := backend.request(ctx, http.MethodPost, endpoint, "application/x-www-form-urlencoded", bytes.NewReader(encoded), 16)
	clearBytes(response)
	return err
}

func (backend *QBitBackend) request(ctx context.Context, method, endpoint, contentType string, body io.Reader, limit int64) ([]byte, error) {
	if backend == nil || backend.doer == nil || ctx == nil || !strings.HasPrefix(endpoint, "/api/v2/") || limit <= 0 || limit > maximumQBitResponse {
		return nil, invalidRequest()
	}
	requestCtx, cancel := boundedContext(ctx, maximumQBitOperation)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, method, qbitBaseURL+endpoint, body)
	if err != nil {
		return nil, errors.New("bounded qBittorrent request failed")
	}
	request.Header.Set("Referer", qbitBaseURL)
	request.Header.Set("Origin", qbitBaseURL)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := backend.doer.Do(request)
	if err != nil {
		if requestCtx.Err() != nil {
			return nil, requestCtx.Err()
		}
		return nil, errors.New("bounded qBittorrent request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("bounded qBittorrent request failed")
	}
	value, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(value)) > limit {
		clearBytes(value)
		return nil, errors.New("bounded qBittorrent response failed")
	}
	return value, nil
}

func decodeStrictJSON(raw []byte, destination any) error {
	defer clearBytes(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing qBittorrent JSON")
	}
	return nil
}

func (backend *QBitBackend) String() string { return fmt.Sprintf("qBittorrent(%s)", qbitBaseURL) }

var _ Backend = (*QBitBackend)(nil)
