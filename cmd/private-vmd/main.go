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
	"github.com/StevenBuglione/private-vm/internal/commandexec"
	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/daemon"
	"github.com/StevenBuglione/private-vm/internal/recovery"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/usb"
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
	cryptsetup, err := trustedToolPath("cryptsetup")
	if err != nil {
		return err
	}
	losetup, err := trustedToolPath("losetup")
	if err != nil {
		return err
	}
	backend, err := recovery.NewLinuxBackend(recovery.LinuxBackendConfig{
		Store: store, ScratchRoot: runtimeConfig.ScratchDirectory(),
		DaemonUID: uint32(os.Geteuid()), DaemonGID: uint32(os.Getegid()), ControlGID: uint32(gid),
		Cryptsetup: cryptsetup, Losetup: losetup,
		Runner: recovery.OSRecoveryRunner{}, Mounter: recovery.UnixMountCleaner{},
	})
	if err != nil {
		return err
	}
	cleanupTimeout := time.Duration(runtimeConfig.CleanupTimeoutSeconds()) * time.Second
	reconciler, err := recovery.New(
		backend,
		recovery.NewStartupRegistry(),
		recovery.VolatileKeyEvidence{RuntimeRoot: runtimeConfig.Directory(), DaemonUID: uint32(os.Geteuid()), DaemonGID: uint32(os.Getegid())},
		recovery.FilesystemBaseAuditor{Root: runtimeConfig.ImageCache(), OwnerUID: uint32(os.Geteuid())},
		recovery.Config{
			DaemonUID: uint32(os.Geteuid()), InventoryTimeout: cleanupTimeout,
			StepTimeout: cleanupTimeout, SessionTimeout: boundedRecoverySessionTimeout(cleanupTimeout),
		},
	)
	if err != nil {
		return err
	}
	recoveryReportPath := filepath.Join(filepath.Dir(runtimeConfig.Directory()), "private-vm-recovery-"+filepath.Base(runtimeConfig.Directory())+".json")
	if err := runStartupRecovery(context.Background(), reconciler.Run, func(report recovery.Report) error {
		return recovery.WriteReportAtomic(recoveryReportPath, report)
	}); err != nil {
		return err
	}
	manager, err := session.NewManager(store, session.DefaultMaxSessionsPerOwner)
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
	usbguard, err := trustedToolPath("usbguard")
	if err != nil {
		return err
	}
	guard := usb.CommandUSBGuard{Executor: commandexec.OSExecutor{CaptureLimit: commandexec.DefaultCaptureLimit}, Binary: usbguard}
	enumerator := usb.Enumerator{Source: usb.DefaultSysfsSource(guard)}
	ownerStores, err := usb.NewOwnerStores(usb.DefaultEnrollmentRoot, uint32(os.Geteuid()))
	if err != nil {
		return err
	}
	usbRegistry, err := usb.NewRegistry(enumerator, ownerStores)
	if err != nil {
		return err
	}
	usbClaims, err := usb.NewClaimManager(enumerator, guard)
	if err != nil {
		return err
	}
	service := &daemon.Service{
		Sessions: manager, Config: cfg, Polkit: daemon.PKCheck{Binary: pkcheck},
		USBRegistry: usbRegistry, USBClaims: usbClaims,
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
			cleanupTimeout,
			server.Shutdown,
			done,
			manager.Shutdown,
		)
	}
}

type startupRecoveryRun func(context.Context) (recovery.Report, error)

func runStartupRecovery(ctx context.Context, run startupRecoveryRun, write func(recovery.Report) error) error {
	if ctx == nil || run == nil || write == nil {
		return errors.New("startup recovery composition is invalid")
	}
	report, recoveryErr := run(ctx)
	writeErr := write(report)
	if writeErr != nil {
		return errors.Join(errors.New("startup recovery report could not be published"), writeErr)
	}
	if recoveryErr != nil || report.Status != recovery.StatusComplete || !report.BaseImagesVerified {
		return errors.Join(recovery.ErrIncomplete, recoveryErr)
	}
	return nil
}

func boundedRecoverySessionTimeout(step time.Duration) time.Duration {
	timeout := step * 4
	if timeout < step {
		return 5 * time.Minute
	}
	if timeout > 5*time.Minute {
		return 5 * time.Minute
	}
	return timeout
}

func trustedToolPath(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", errors.New("required recovery tool is unavailable")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", errors.New("required recovery tool path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Base(resolved) != name {
		return "", errors.New("required recovery tool identity is invalid")
	}
	return resolved, nil
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
