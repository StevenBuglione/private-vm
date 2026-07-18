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
