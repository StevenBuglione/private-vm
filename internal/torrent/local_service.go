package torrent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

const (
	qbitRuntimeRoot        = "/run/private-vm-qbittorrent"
	qbitConfigPath         = qbitRuntimeRoot + "/config/qBittorrent/qBittorrent.conf"
	qbitUsername           = "private-vm"
	qbitLoginURL           = qbitBaseURL + "/api/v2/auth/login"
	qbitLoginTimeout       = 15 * time.Second
	qbitCredentialBytes    = 32
	qbitSaltBytes          = 16
	qbitPasswordKeyBytes   = 64
	qbitPasswordIterations = 100000
)

var qbitSIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

type localServiceManager interface {
	Start(context.Context) error
	Stop(context.Context) error
}

// LocalQBittorrentService owns one per-boot credential, one fixed qBittorrent
// child process and the authenticated loopback HTTP client. It cannot select
// another executable, URL, profile or save path.
type LocalQBittorrentService struct {
	mu         sync.Mutex
	manager    localServiceManager
	client     HTTPDoer
	password   *secret.Bytes
	cookie     *secret.Bytes
	configPath string
	started    bool
	wait       func(context.Context, time.Duration) error
}

type qbitConfigWriter func(string, []byte, int, int) error

func NewLocalQBittorrentService(qbittorrentPath string, privateUID, privateGID int) (*LocalQBittorrentService, error) {
	manager, err := newQBittorrentProcessManager(qbittorrentPath, privateUID, privateGID)
	if err != nil {
		return nil, err
	}
	return newLocalQBittorrentService(manager, fixedLoopbackClient(), qbitConfigPath, privateUID, privateGID, rand.Reader, writePrivateQBitConfig)
}

func newLocalQBittorrentService(manager localServiceManager, client HTTPDoer, configPath string, uid, gid int, random io.Reader, writer qbitConfigWriter) (*LocalQBittorrentService, error) {
	if nilLike(manager) || nilLike(client) || nilLike(random) || writer == nil || !filepath.IsAbs(configPath) || filepath.Clean(configPath) != configPath || uid <= 0 || gid <= 0 {
		return nil, invalidRequest()
	}
	raw := make([]byte, qbitCredentialBytes)
	if _, err := io.ReadFull(random, raw); err != nil {
		clearBytes(raw)
		return nil, errors.New("per-boot qBittorrent credential unavailable")
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(encoded, raw)
	clearBytes(raw)
	password, err := secret.New(encoded)
	clearBytes(encoded)
	if err != nil {
		return nil, errors.New("per-boot qBittorrent credential unavailable")
	}
	service := &LocalQBittorrentService{
		manager: manager, client: client, password: password, configPath: configPath,
		wait: func(ctx context.Context, duration time.Duration) error {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}
	if err := service.writeConfiguration(uid, gid, random, writer); err != nil {
		password.Destroy()
		return nil, err
	}
	return service, nil
}

func fixedLoopbackClient() *http.Client {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "127.0.0.1:8080" {
				return nil, errors.New("qBittorrent Web API target rejected")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
		},
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("qBittorrent redirect rejected")
	}}
}

func (service *LocalQBittorrentService) Start(ctx context.Context) error {
	if service == nil || ctx == nil {
		return invalidRequest()
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.started && service.cookie != nil {
		return nil
	}
	operationCtx, cancel := boundedContext(ctx, qbitLoginTimeout)
	defer cancel()
	// Claim ownership before requesting start: cancellation can race with exec
	// and login, so every error path must stop/audit the fixed child instead of
	// assuming it never started.
	service.started = true
	if err := service.manager.Start(operationCtx); err != nil {
		service.stopAfterFailure()
		return err
	}
	for {
		cookie, err := service.login(operationCtx)
		if err == nil {
			if service.cookie != nil {
				service.cookie.Destroy()
			}
			service.cookie = cookie
			return nil
		}
		if operationCtx.Err() != nil {
			service.stopAfterFailure()
			return operationCtx.Err()
		}
		if err := service.wait(operationCtx, 100*time.Millisecond); err != nil {
			service.stopAfterFailure()
			return err
		}
	}
}

func (service *LocalQBittorrentService) Stop(ctx context.Context) error {
	if service == nil || ctx == nil {
		return invalidRequest()
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.cookie != nil {
		service.cookie.Destroy()
		service.cookie = nil
	}
	if !service.started {
		return nil
	}
	if err := service.manager.Stop(ctx); err != nil {
		return err
	}
	service.started = false
	return nil
}

func (service *LocalQBittorrentService) Do(request *http.Request) (*http.Response, error) {
	if service == nil || request == nil || request.URL == nil || request.URL.Scheme != "http" || request.URL.Host != "127.0.0.1:8080" || request.URL.Path == "/api/v2/auth/login" {
		return nil, errors.New("authenticated qBittorrent request rejected")
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if !service.started || service.cookie == nil {
		return nil, errors.New("authenticated qBittorrent service unavailable")
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	var response *http.Response
	err := service.cookie.WithReader(func(reader io.Reader) error {
		value, err := io.ReadAll(io.LimitReader(reader, 129))
		if err != nil || !qbitSIDPattern.Match(value) {
			clearBytes(value)
			return errors.New("qBittorrent session unavailable")
		}
		clone.Header.Set("Cookie", "SID="+string(value))
		clearBytes(value)
		response, err = service.client.Do(clone)
		clone.Header.Del("Cookie")
		return err
	})
	if err != nil {
		return nil, errors.New("authenticated qBittorrent request failed")
	}
	return response, nil
}

func (service *LocalQBittorrentService) Close(ctx context.Context) error {
	if service == nil {
		return nil
	}
	err := service.Stop(ctx)
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.password != nil {
		service.password.Destroy()
		service.password = nil
	}
	return err
}

func (service *LocalQBittorrentService) login(ctx context.Context) (*secret.Bytes, error) {
	var body bytes.Buffer
	_, _ = body.WriteString("username=" + qbitUsername + "&password=")
	err := service.password.WithReader(func(reader io.Reader) error {
		_, err := io.CopyN(&body, reader, int64(base64.RawURLEncoding.EncodedLen(qbitCredentialBytes)))
		return err
	})
	defer clearBytes(body.Bytes())
	if err != nil {
		return nil, errors.New("qBittorrent login material unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, qbitLoginURL, bytes.NewReader(body.Bytes()))
	if err != nil {
		return nil, errors.New("qBittorrent login request failed")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", qbitBaseURL)
	request.Header.Set("Referer", qbitBaseURL)
	response, err := service.client.Do(request)
	if err != nil {
		return nil, errors.New("qBittorrent login request failed")
	}
	defer response.Body.Close()
	value, err := io.ReadAll(io.LimitReader(response.Body, 17))
	defer clearBytes(value)
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(value, []byte("Ok.")) {
		return nil, errors.New("qBittorrent login rejected")
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == "SID" && qbitSIDPattern.MatchString(cookie.Value) {
			raw := []byte(cookie.Value)
			result, createErr := secret.New(raw)
			clearBytes(raw)
			return result, createErr
		}
	}
	return nil, errors.New("qBittorrent login cookie missing")
}

func (service *LocalQBittorrentService) stopAfterFailure() {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if service.manager.Stop(cleanupCtx) == nil {
		service.started = false
	}
}

func (service *LocalQBittorrentService) writeConfiguration(uid, gid int, random io.Reader, writer qbitConfigWriter) error {
	salt := make([]byte, qbitSaltBytes)
	if _, err := io.ReadFull(random, salt); err != nil {
		clearBytes(salt)
		return errors.New("qBittorrent configuration salt unavailable")
	}
	var passwordBytes []byte
	if err := service.password.WithReader(func(reader io.Reader) error {
		var err error
		passwordBytes, err = io.ReadAll(io.LimitReader(reader, 128))
		return err
	}); err != nil {
		clearBytes(salt)
		clearBytes(passwordBytes)
		return errors.New("qBittorrent configuration credential unavailable")
	}
	derived := pbkdf2SHA512(passwordBytes, salt, qbitPasswordIterations)
	clearBytes(passwordBytes)
	hash := base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(derived)
	clearBytes(salt)
	clearBytes(derived)
	config := []byte("[Application]\nFileLogger\\Enabled=false\n\n[AutoRun]\nConsoleEnabled=false\nOnTorrentAdded\\Enabled=false\nenabled=false\n\n[BitTorrent]\nSession\\AddTorrentStopped=true\nSession\\AnonymousModeEnabled=true\nSession\\DefaultSavePath=" + QuarantineDownloadDir + "/\nSession\\DHTEnabled=false\nSession\\FinishedTorrentExportDirectory=\nSession\\Interface=proton0\nSession\\InterfaceName=proton0\nSession\\LSDEnabled=false\nSession\\PeXEnabled=false\nSession\\ShareLimitAction=Stop\nSession\\TempPath=" + QuarantineMountPath + "/.incomplete/\nSession\\TempPathEnabled=true\nSession\\TorrentExportDirectory=\n\n[Network]\nPortForwardingEnabled=false\n\n[Preferences]\nAdvanced\\trackerPortForwarding=false\nWebUI\\Address=127.0.0.1\nWebUI\\AuthSubnetWhitelistEnabled=false\nWebUI\\CSRFProtection=true\nWebUI\\ClickjackingProtection=true\nWebUI\\Enabled=true\nWebUI\\HostHeaderValidation=true\nWebUI\\LocalHostAuth=true\nWebUI\\Password_PBKDF2=\"@ByteArray(" + hash + ")\"\nWebUI\\Port=8080\nWebUI\\ServerDomains=localhost\nWebUI\\UseUPnP=false\nWebUI\\Username=" + qbitUsername + "\n")
	hash = ""
	defer clearBytes(config)
	return writer(service.configPath, config, uid, gid)
}

func pbkdf2SHA512(password, salt []byte, iterations int) []byte {
	block := make([]byte, len(salt)+4)
	copy(block, salt)
	binary.BigEndian.PutUint32(block[len(salt):], 1)
	mac := hmac.New(sha512.New, password)
	_, _ = mac.Write(block)
	current := mac.Sum(nil)
	result := append([]byte(nil), current...)
	clearBytes(block)
	for index := 1; index < iterations; index++ {
		mac.Reset()
		_, _ = mac.Write(current)
		next := mac.Sum(nil)
		for position := range result {
			result[position] ^= next[position]
		}
		clearBytes(current)
		current = next
	}
	clearBytes(current)
	return result
}

func writePrivateQBitConfig(path string, value []byte, uid, gid int) error {
	parent := filepath.Dir(path)
	root := filepath.Dir(filepath.Dir(parent))
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return errors.New("volatile qBittorrent configuration directory unavailable")
	}
	for current := parent; current != filepath.Dir(root); current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("volatile qBittorrent configuration directory unsafe")
		}
		if err := os.Chown(current, 0, gid); err != nil || os.Chmod(current, 0o750) != nil {
			return errors.New("volatile qBittorrent configuration directory unavailable")
		}
	}
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o440)
	if err != nil {
		return errors.New("volatile qBittorrent configuration unavailable")
	}
	file := os.NewFile(uintptr(fd), "qBittorrent.conf")
	defer file.Close()
	info, err := file.Stat()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || (stat.Uid != 0 && stat.Uid != uint32(uid)) {
		return errors.New("volatile qBittorrent configuration unsafe")
	}
	if err := file.Chown(0, gid); err != nil || file.Chmod(0o440) != nil || file.Truncate(0) != nil {
		return errors.New("volatile qBittorrent configuration unavailable")
	}
	if _, err := file.Write(value); err != nil || file.Sync() != nil {
		return errors.New("volatile qBittorrent configuration unavailable")
	}
	return nil
}

func (service *LocalQBittorrentService) String() string {
	return fmt.Sprintf("qBittorrentService(%s)", qbitBaseURL)
}

var _ HTTPDoer = (*LocalQBittorrentService)(nil)
