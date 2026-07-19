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
	"strings"
	"syscall"
	"time"

	"github.com/StevenBuglione/private-vm/internal/buildinfo"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/session"
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
	serverConfig, scannerService, err := composeGuestServerConfig(identity, token)
	if err != nil {
		fatal("GUESTD_SERVER_INVALID", "the role-specific guest service could not be composed", "Destroy the guest and install a compatible verified image.")
	}
	if scannerService != nil {
		defer func() {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = scannerService.Close(cleanupContext)
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

func composeGuestServerConfig(identity guest.Identity, token *guest.Token) (guest.ServerConfig, *guest.ScannerService, error) {
	config := guest.ServerConfig{Identity: identity, Token: token}
	switch identity.Role {
	case session.RoleWorkstation:
		workspace, err := workstation.New(workstation.Config{Root: "/home/private"})
		if err != nil {
			return guest.ServerConfig{}, nil, err
		}
		config.Workstation = workspace
		return config, nil, nil
	case session.RoleScanner:
		// Continue below and install only the scanner service compiled for this role.
	case session.RoleExporter:
		return guest.ServerConfig{}, nil, errors.New("fixed-path exporter LUKS2/ext4 adapter is not configured")
	default:
		return config, nil, nil
	}
	scannerService, err := guest.NewFailClosedScannerService(identity, token)
	if err != nil {
		return guest.ServerConfig{}, nil, err
	}
	config.Scanner = scannerService
	return config, scannerService, nil
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
