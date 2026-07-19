//go:build linux

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/session"
)

var remoteViewerCandidates = []string{
	"/run/current-system/sw/bin/remote-viewer",
	"/usr/bin/remote-viewer",
	"/usr/local/bin/remote-viewer",
}

func launchRemoteViewer(ctx context.Context, sessionID string) error {
	if ctx == nil || session.ValidateID(sessionID) != nil {
		return errors.New("display request is invalid")
	}
	executable, err := resolveRemoteViewer()
	if err != nil {
		return err
	}
	socket := filepath.Join(config.DefaultRuntimePath, "display", sessionID+".sock")
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return errors.New("display handoff socket is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("display handoff socket ownership is invalid")
	}
	command := exec.CommandContext(ctx, executable, "spice+unix://"+socket)
	command.Env = viewerEnvironment()
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	return command.Run()
}

func resolveRemoteViewer() (string, error) {
	for _, candidate := range remoteViewerCandidates {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
			continue
		}
		if candidate == remoteViewerCandidates[0] && !strings.HasPrefix(resolved, "/nix/store/") {
			continue
		}
		info, err := os.Lstat(resolved)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			continue
		}
		return resolved, nil
	}
	return "", errors.New("trusted remote-viewer executable is unavailable")
}

func viewerEnvironment() []string {
	names := []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "LANG"}
	result := make([]string, 0, len(names))
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok && !strings.ContainsAny(value, "\x00\r\n") {
			result = append(result, name+"="+value)
		}
	}
	return result
}
