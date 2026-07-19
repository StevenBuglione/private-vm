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
	manager, err := session.NewManager(store, 4)
	if err != nil {
		return err
	}
	pkcheck, err := exec.LookPath("pkcheck")
	if err != nil {
		return errors.New("pkcheck is required for destructive USB authorization")
	}
	pkcheck, err = filepath.Abs(pkcheck)
	if err != nil {
		return fmt.Errorf("resolve pkcheck: %w", err)
	}
	service := &daemon.Service{Sessions: manager, Config: cfg, Polkit: daemon.PKCheck{Binary: pkcheck}}
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
		shutdownContext, cancel := context.WithTimeout(
			context.Background(),
			time.Duration(runtimeConfig.CleanupTimeoutSeconds())*time.Second,
		)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("bounded daemon shutdown: %w", err)
		}
		return <-done
	}
}
