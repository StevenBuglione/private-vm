package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/StevenBuglione/private-vm/internal/buildinfo"
	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/daemon"
	"github.com/StevenBuglione/private-vm/internal/session"
)

const daemonStartupFailureMessage = "private-vmd: DAEMON_START_FAILED: the daemon could not start; inspect redacted system service diagnostics and verify the installed configuration"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, daemonStartupFailureMessage)
		os.Exit(1)
	}
}

func run() error {
	var version bool
	var configPath string
	var groupName string
	flag.BoolVar(&version, "version", false, "print build information")
	flag.StringVar(&configPath, "config", config.DefaultSystemPath, "system configuration file")
	flag.StringVar(&groupName, "group", "private-vm", "authorized daemon socket group")
	flag.Parse()

	if version {
		return json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
	}
	if os.Geteuid() != 0 {
		return errors.New("private-vmd must run as root")
	}
	cfg, err := config.LoadDaemon(configPath)
	if err != nil {
		return err
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return fmt.Errorf("resolve daemon group %q: %w", groupName, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		return fmt.Errorf("daemon group %q has an invalid numeric ID", groupName)
	}
	runtimeConfig := cfg.Runtime()
	store, err := session.NewStore(runtimeConfig.Directory())
	if err != nil {
		return err
	}
	manager, err := session.NewManager(store, session.DefaultMaxSessionsPerOwner)
	if err != nil {
		return err
	}
	hostServices, err := composeProductionHost(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer hostServices.Close()
	pkcheck, err := exec.LookPath("pkcheck")
	if err != nil {
		return errors.New("pkcheck is required for destructive USB authorization")
	}
	pkcheck, err = filepath.Abs(pkcheck)
	if err != nil {
		return fmt.Errorf("resolve pkcheck: %w", err)
	}
	service := &daemon.Service{
		Sessions: manager, Config: cfg, Polkit: daemon.PKCheck{Binary: pkcheck},
		Profiles: hostServices.profiles, VPNResolver: hostServices.resolver,
		Roles: hostServices.roles, Torrents: hostServices.roles,
	}
	server, err := daemon.NewServer(daemon.ServerOptions{
		SocketPath: filepath.Join(runtimeConfig.Directory(), "control.sock"),
		OwnerUID:   0,
		GroupGID:   gid,
		Service:    service,
		Authorizer: daemon.Authorizer{AllowedGroup: uint32(gid)},
	})
	if err != nil {
		return err
	}
	if err := server.Listen(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return shutdownServices(
			time.Duration(runtimeConfig.CleanupTimeoutSeconds())*time.Second,
			server.Shutdown,
			done,
			manager.Shutdown,
		)
	}
}

func shutdownServices(
	timeout time.Duration,
	serverShutdown func(context.Context) error,
	serverDone <-chan error,
	managerShutdown func(context.Context) error,
) error {
	if timeout <= 0 || serverShutdown == nil || serverDone == nil || managerShutdown == nil {
		return errors.New("daemon shutdown configuration is invalid")
	}

	serverContext, cancelServer := context.WithTimeout(context.Background(), timeout)
	serverErr := serverShutdown(serverContext)
	cancelServer()

	// A server implementation must normally finish Serve when Shutdown returns,
	// but bound this observation independently so a broken server cannot prevent
	// session cleanup from being admitted.
	serveWaitContext, cancelServeWait := context.WithTimeout(context.Background(), timeout)
	var serveErr error
	select {
	case serveErr = <-serverDone:
	case <-serveWaitContext.Done():
		serveErr = serveWaitContext.Err()
	}
	cancelServeWait()

	// Session cleanup gets its own full budget. It must run even when graceful
	// server shutdown or the Serve result failed.
	managerContext, cancelManager := context.WithTimeout(context.Background(), timeout)
	managerErr := managerShutdown(managerContext)
	cancelManager()

	var shutdownErrors []error
	if serverErr != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("bounded daemon shutdown: %w", serverErr))
	}
	if serveErr != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("daemon serve termination: %w", serveErr))
	}
	if managerErr != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("bounded session cleanup: %w", managerErr))
	}
	return errors.Join(shutdownErrors...)
}
