package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const commandOutputLimit = 64 << 10

type Command struct {
	Path       string
	Args       []string
	ExtraFiles []*os.File
}

type Result struct {
	Stdout []byte
}

type Runner interface {
	Run(context.Context, Command) (Result, error)
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, command Command) (Result, error) {
	if !filepath.IsAbs(command.Path) || filepath.Clean(command.Path) != command.Path {
		return Result{}, errors.New("external command path must be a clean absolute path")
	}
	if err := verifyStorageExecutable(command.Path); err != nil {
		return Result{}, err
	}
	cmd := exec.CommandContext(ctx, command.Path, command.Args...)
	cmd.Env = []string{"LANG=C.UTF-8"}
	cmd.ExtraFiles = command.ExtraFiles
	var stdout limitedBuffer
	stdout.limit = commandOutputLimit
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if stdout.exceeded {
		return Result{}, errors.New("external command output exceeded 64 KiB")
	}
	if err != nil {
		return Result{}, fmt.Errorf("external command failed: %w", err)
	}
	return Result{Stdout: append([]byte(nil), stdout.Bytes()...)}, nil
}

func verifyStorageExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("storage tool is unavailable or has unsafe type or mode")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("storage tool path must not contain symbolic links")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return errors.New("storage tool owner is not trusted")
	}
	current := filepath.Dir(path)
	for current != "/" {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("storage tool ancestor is unavailable or symbolic")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
			return errors.New("storage tool ancestor owner is not trusted")
		}
		if info.Mode().Perm()&0o022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return errors.New("storage tool ancestor is writable by an untrusted group or user")
		}
		next := filepath.Dir(current)
		if next == current {
			break
		}
		current = next
	}
	return nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	if b.Len()+len(value) > b.limit {
		remaining := b.limit - b.Len()
		if remaining > 0 {
			_, _ = b.Buffer.Write(value[:remaining])
		}
		b.exceeded = true
		return len(value), nil
	}
	return b.Buffer.Write(value)
}
