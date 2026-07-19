package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/StevenBuglione/private-vm/internal/buildinfo"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/torrent"
	"github.com/StevenBuglione/private-vm/internal/workstation"
	"google.golang.org/grpc"
)

func main() {
	var version bool
	flags := flag.NewFlagSet("private-vm-guestd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&version, "version", false, "print build information")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fatal("GUESTD_ARGUMENT_INVALID", "guestd received an unsupported argument", "Remove runtime role or transport arguments; those values are fixed by the verified image.")
	}

	if version {
		_ = json.NewEncoder(os.Stdout).Encode(currentVersion())
		return
	}

	if flags.NArg() != 0 {
		fatal("GUESTD_ARGUMENT_INVALID", "guestd does not accept positional arguments", "Remove runtime role or transport arguments; those values are fixed by the verified image.")
	}
	role, err := guest.CompiledSessionRole()
	if err != nil {
		fatal("GUESTD_ROLE_INVALID", err.Error(), "Install the guestd derivation compiled for this image role.")
	}
	token, err := guest.ReadToken(guest.FWCfgTokenPath)
	if err != nil {
		fatal("GUESTD_CAPABILITY_UNAVAILABLE", err.Error(), "Destroy the guest and start it through private-vmd so a fresh fw_cfg capability is injected.")
	}
	defer token.Destroy()

	info := buildinfo.Current()
	identity, err := guest.NewIdentity(role, guest.ImageDigest, info.Commit, osRelease(), info.Version)
	if err != nil {
		fatal("GUESTD_IDENTITY_INVALID", err.Error(), "Install a verified role image with complete build identity metadata.")
	}
	serverConfig, roleCleanup, err := composeGuestServerConfig(identity, token)
	if err != nil {
		fatal("GUESTD_SERVER_INVALID", guestCompositionMessage(err), "Destroy the guest and install a compatible verified image.")
	}
	if roleCleanup != nil {
		defer func() {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = roleCleanup.Close(cleanupContext)
		}()
	}
	server, err := guest.NewServer(serverConfig)
	if err != nil {
		fatal("GUESTD_SERVER_INVALID", err.Error(), "Destroy the guest and install a compatible verified image.")
	}
	listener, err := guest.Listen(guest.DefaultPort)
	if err != nil {
		fatal("GUESTD_LISTEN_FAILED", err.Error(), "Verify the guest VSOCK device and kernel transport, then recreate the session.")
	}
	defer listener.Close()

	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			fatal("GUESTD_SERVE_FAILED", err.Error(), "Destroy the guest and retry with a verified image and VSOCK device.")
		}
	case <-ctx.Done():
		stopped := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			server.Stop()
			<-stopped
		}
		if err := <-serveErr; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			fatal("GUESTD_SERVE_FAILED", err.Error(), "Destroy the guest and retry with a verified image and VSOCK device.")
		}
	}
}

type roleCleanup interface {
	Close(context.Context) error
}

type guestCompositionError struct {
	message string
}

func (failure *guestCompositionError) Error() string {
	return failure.message
}

func compositionError(message string) error {
	return &guestCompositionError{message: message}
}

func guestCompositionMessage(err error) string {
	var failure *guestCompositionError
	if errors.As(err, &failure) {
		return failure.Error()
	}
	return "the role-specific guest service could not be composed"
}

func composeGuestServerConfig(identity guest.Identity, token *guest.Token) (guest.ServerConfig, roleCleanup, error) {
	config := guest.ServerConfig{Identity: identity, Token: token}
	switch identity.Role {
	case session.RoleWorkstation:
		workspace, err := workstation.New(workstation.Config{Root: "/home/private"})
		if err != nil {
			return guest.ServerConfig{}, nil, err
		}
		network, err := guest.NewWorkstationVPNServer(workspace, productionVPNFactory(session.RoleWorkstation, nil))
		if err != nil {
			return guest.ServerConfig{}, nil, err
		}
		config.Workstation = network
		return config, network, nil
	case session.RoleScanner:
		// Continue below and install only the scanner service compiled for this role.
	case session.RoleDownloader:
		downloader, cleanup, err := composeDownloaderService()
		if err != nil {
			return guest.ServerConfig{}, nil, err
		}
		config.Downloader = downloader
		return config, cleanup, nil
	default:
		return config, nil, nil
	}
	scannerService, err := guest.NewFailClosedScannerService(identity, token)
	if err != nil {
		return guest.ServerConfig{}, nil, err
	}
	scannerNetwork, err := guest.NewScannerVPNServer(scannerService, productionVPNFactory(session.RoleScanner, nil))
	if err != nil {
		return guest.ServerConfig{}, nil, err
	}
	config.Scanner = scannerNetwork
	return config, scannerNetwork, nil
}

type downloaderCleanup struct {
	server     *guest.DownloaderVPNServer
	controller *torrent.Controller
	client     *torrent.LocalQBittorrentService
	quarantine *torrent.QuarantineOwner
}

func (cleanup *downloaderCleanup) Close(ctx context.Context) error {
	if cleanup == nil {
		return nil
	}
	var cleanupErrors []error
	if cleanup.controller != nil {
		if err := cleanup.controller.Close(ctx); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	var vpnErr error
	if cleanup.server != nil {
		vpnErr = cleanup.server.StopVPN(ctx)
		if vpnErr != nil && cleanup.client != nil {
			// A failed first child stop retains ownership. Retry the fixed process,
			// then let the VPN owner finish tunnel -> kill-switch teardown.
			if retryErr := cleanup.client.Stop(ctx); retryErr == nil {
				vpnErr = cleanup.server.StopVPN(ctx)
			} else {
				vpnErr = errors.Join(vpnErr, retryErr)
			}
		}
	}
	if cleanup.client != nil {
		if err := cleanup.client.Close(ctx); err != nil {
			vpnErr = errors.Join(vpnErr, err)
		}
	}
	if vpnErr != nil {
		cleanupErrors = append(cleanupErrors, vpnErr)
		// qBittorrent may still own quarantine paths. Preserve the mount for
		// process/VM teardown instead of unmounting beneath an active process.
		return errors.Join(cleanupErrors...)
	}
	if cleanup.quarantine != nil {
		if err := cleanup.quarantine.Close(ctx); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return errors.Join(cleanupErrors...)
}

func composeDownloaderService() (*guest.DownloaderVPNServer, *downloaderCleanup, error) {
	prepareCtx, cancelPrepare := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelPrepare()
	uid, gid, err := privateUserIdentity()
	if err != nil {
		return nil, nil, compositionError("the downloader private user identity is unavailable")
	}
	quarantine, err := torrent.PrepareLinuxQuarantine(prepareCtx, "/run/current-system/sw/bin/mkfs.ext4", uid, gid)
	if err != nil {
		return nil, nil, compositionError(downloaderQuarantineFailure(err))
	}
	fail := func(err error) (*guest.DownloaderVPNServer, *downloaderCleanup, error) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = quarantine.Close(cleanupCtx)
		return nil, nil, err
	}
	available, err := quarantine.CapacityBytes()
	if err != nil || available <= 6<<30 {
		return fail(compositionError("the downloader quarantine capacity check failed"))
	}
	client, err := torrent.NewLocalQBittorrentService("/etc/private-vm/qbittorrent", uid, gid)
	if err != nil {
		return fail(compositionError("the downloader qBittorrent configuration failed"))
	}
	backend, err := torrent.NewQBitBackend(client, torrent.NewFilesystemVerifier())
	if err != nil {
		_ = client.Close(context.Background())
		return fail(compositionError("the downloader qBittorrent backend failed"))
	}
	maximumSelected := (available - (5 << 30)) / 2
	controller, err := torrent.NewController(backend, quarantine, torrent.Config{
		SafePolicy: true,
		Budget: torrent.CapacityBudget{
			QuarantineAvailableBytes: available, ScanAvailableBytes: available, ReconstructionAvailable: available,
			DestinationAvailable: available, RootOverlayBudgetBytes: 1 << 30, ArchiveExpansionBytes: 4 << 30,
			ReconstructionBytes: 1 << 30, MaximumSelectedBytes: maximumSelected,
		},
	})
	if err != nil {
		_ = client.Close(context.Background())
		return fail(compositionError("the downloader controller failed"))
	}
	factory := productionVPNFactory(session.RoleDownloader, client)
	server, err := guest.NewDownloaderServer(factory, controller)
	if err != nil {
		_ = controller.Close(context.Background())
		_ = client.Close(context.Background())
		return fail(compositionError("the downloader authenticated service failed"))
	}
	cleanup := &downloaderCleanup{server: server, controller: controller, client: client, quarantine: quarantine}
	return server, cleanup, nil
}

func downloaderQuarantineFailure(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "the downloader quarantine initialization timed out"
	}
	switch err.Error() {
	case "fixed quarantine device unavailable":
		return "the downloader quarantine device is unavailable"
	case "fixed quarantine device is not block storage":
		return "the downloader quarantine device type is invalid"
	case "fixed quarantine device identity mismatch":
		return "the downloader quarantine device identity is invalid"
	case "fixed quarantine device is not writable":
		return "the downloader quarantine device is read-only"
	case "fixed quarantine capacity unavailable", "fixed quarantine capacity invalid":
		return "the downloader quarantine device capacity is invalid"
	case "quarantine mount evidence unavailable":
		return "the downloader quarantine mount evidence is unavailable"
	case "quarantine filesystem preparation failed":
		return "the downloader quarantine filesystem preparation failed"
	case "quarantine mount failed":
		return "the downloader quarantine mount failed"
	case "quarantine preparation cleanup incomplete":
		return "the downloader quarantine rollback audit failed"
	case "quarantine directory preparation failed":
		return "the downloader quarantine directory preparation failed"
	default:
		return "the downloader quarantine initialization failed"
	}
}

type prohibitedTorrentBindingProbe struct{}

func (prohibitedTorrentBindingProbe) Bound(context.Context) (bool, error) {
	return false, errors.New("torrent binding is unavailable outside the downloader role")
}

func productionVPNFactory(role session.Role, client *torrent.LocalQBittorrentService) guest.DownloaderControllerFactory {
	return func(underlay guestvpn.Underlay, targets guestvpn.ProbeTargets) (*guestvpn.Controller, error) {
		networkBackend, err := guestvpn.NewLinuxBackend(guestvpn.ToolPaths{
			IP: "/run/current-system/sw/bin/ip", NFT: "/run/current-system/sw/bin/nft", WG: "/run/current-system/sw/bin/wg",
		}, guestvpn.NewSystemdResolvedDNS())
		if err != nil {
			return nil, err
		}
		handshake, err := guestvpn.NewWireGuardHandshakeProbe("/run/current-system/sw/bin/wg")
		if err != nil {
			return nil, err
		}
		bindingProbe := guestvpn.TorrentBindingProbe(prohibitedTorrentBindingProbe{})
		policy := guestvpn.RolePolicy{Role: role, ScannerUpdate: role == session.RoleScanner}
		if role == session.RoleDownloader {
			if client == nil {
				return nil, errors.New("downloader qBittorrent owner is unavailable")
			}
			bindingProbe = guestvpn.NewQBittorrentBindingProbeWithClient(client)
			policy.RequireTorrentBinding = true
		}
		verifier, err := guestvpn.NewControlledVerifier(
			handshake, guestvpn.NewResolvedDNSLeakProbe(), guestvpn.NewBoundTCPProbe(),
			bindingProbe, targets,
		)
		if err != nil {
			return nil, err
		}
		if role == session.RoleWorkstation || role == session.RoleScanner {
			return guestvpn.NewController(networkBackend, verifier, policy, underlay)
		}
		return guestvpn.NewControllerWithOnlineService(
			networkBackend, verifier, client, policy, underlay,
		)
	}
}

func privateUserIdentity() (int, int, error) {
	account, err := user.Lookup("private")
	if err != nil {
		return 0, 0, errors.New("private downloader user is unavailable")
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
		return 0, 0, errors.New("private downloader user identity is invalid")
	}
	return uid, gid, nil
}

type versionRecord struct {
	buildinfo.Info
	GuestRole    string   `json:"guestRole"`
	Capabilities []string `json:"capabilities"`
	APIMajor     uint32   `json:"guestApiMajor"`
	APIMinor     uint32   `json:"guestApiMinor"`
}

func currentVersion() versionRecord {
	record := versionRecord{
		Info: buildinfo.Current(), GuestRole: "uncompiled", Capabilities: []string{},
		APIMajor: guest.APIMajor, APIMinor: guest.APIMinor,
	}
	role, err := guest.CompiledSessionRole()
	if err != nil {
		return record
	}
	record.GuestRole = string(role)
	record.Capabilities, _ = guest.Capabilities(role)
	return record
}

func osRelease() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 32<<10))
	scanner.Buffer(make([]byte, 1024), 32<<10)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if found && key == "VERSION_ID" {
			value = strings.Trim(value, "\"")
			if value != "" && len(value) <= 64 && !strings.ContainsAny(value, "\x00\r\n") {
				return value
			}
		}
	}
	return "unknown"
}

func fatal(code, message, remediation string) {
	fmt.Fprintf(os.Stderr, "private-vm-guestd: %s: %s Remediation: %s\n", code, message, remediation)
	os.Exit(20)
}
