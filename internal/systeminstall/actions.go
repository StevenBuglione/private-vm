package systeminstall

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const actionTimeout = 45 * time.Second

type systemActions struct{}

func (systemActions) Activate(ctx context.Context) error {
	steps := []struct {
		candidates []string
		arguments  []string
	}{
		{[]string{"/usr/bin/systemd-sysusers", "/bin/systemd-sysusers"}, []string{"/usr/lib/sysusers.d/private-vm.conf"}},
		{[]string{"/usr/bin/systemd-tmpfiles", "/bin/systemd-tmpfiles"}, []string{"--create", "/usr/lib/tmpfiles.d/private-vm.conf"}},
		{[]string{"/usr/bin/systemctl", "/bin/systemctl"}, []string{"daemon-reload"}},
		{[]string{"/usr/bin/systemctl", "/bin/systemctl"}, []string{"enable", "--now", "private-vmd.service"}},
	}
	for _, step := range steps {
		if err := runExact(ctx, step.candidates, step.arguments...); err != nil {
			return err
		}
	}
	return nil
}

func (systemActions) Deactivate(ctx context.Context) error {
	if err := runExact(ctx, []string{"/usr/bin/systemctl", "/bin/systemctl"}, "disable", "--now", "private-vmd.service"); err != nil {
		return err
	}
	return runExact(ctx, []string{"/usr/bin/systemctl", "/bin/systemctl"}, "daemon-reload")
}

func (systemActions) Reload(ctx context.Context) error {
	return runExact(ctx, []string{"/usr/bin/systemctl", "/bin/systemctl"}, "daemon-reload")
}

func runExact(parent context.Context, candidates []string, arguments ...string) error {
	if parent == nil {
		return errors.New("system action context is unavailable")
	}
	binary := ""
	for _, candidate := range candidates {
		if trustedSystemExecutable(candidate) {
			absolute, absErr := filepath.Abs(candidate)
			if absErr == nil && absolute == candidate {
				binary = candidate
				break
			}
		}
	}
	if binary == "" {
		return errors.New("required system integration command is unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, actionTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env = []string{}
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("bounded system integration command failed")
	}
	return nil
}

func systemdUnitActive(parent context.Context, unit string) (bool, error) {
	binary := ""
	for _, candidate := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if trustedSystemExecutable(candidate) {
			binary = candidate
			break
		}
	}
	if binary == "" {
		return false, errors.New("systemctl is unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, actionTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "is-active", "--quiet", unit)
	command.Env = []string{}
	command.Stdout = nil
	command.Stderr = nil
	err := command.Run()
	if err == nil {
		return true, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && (exitError.ExitCode() == 3 || exitError.ExitCode() == 4) {
		return false, nil
	}
	return false, errors.New("systemd unit activity probe failed")
}

func trustedSystemExecutable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		parentInfo, parentErr := os.Lstat(parent)
		if parentErr != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
			return false
		}
		parentStat, parentOK := parentInfo.Sys().(*syscall.Stat_t)
		if !parentOK || parentStat.Uid != 0 {
			return false
		}
		if parent == "/" {
			return true
		}
	}
}
