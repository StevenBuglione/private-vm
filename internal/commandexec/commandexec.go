package commandexec

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
)

const DefaultCaptureLimit = 1 << 20

type Result struct {
	Stdout []byte
	Stderr []byte
}

type Executor interface {
	Run(ctx context.Context, absolutePath string, args ...string) (Result, error)
}

type OSExecutor struct {
	CaptureLimit int
}

func (e OSExecutor) Run(ctx context.Context, absolutePath string, args ...string) (Result, error) {
	return e.run(ctx, absolutePath, args...)
}

func (e OSExecutor) run(ctx context.Context, absolutePath string, args ...string) (Result, error) {
	if len(absolutePath) == 0 || absolutePath[0] != '/' {
		return Result{}, fmt.Errorf("executable path must be absolute")
	}
	limit := e.CaptureLimit
	if limit <= 0 {
		limit = DefaultCaptureLimit
	}
	cmd := exec.CommandContext(ctx, absolutePath, args...)
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = limit, limit
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, fmt.Errorf("external command output exceeded %d bytes", limit)
	}
	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, err
}

type limitedBuffer struct {
	b        bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.b.Len()+len(p) > b.limit {
		remaining := b.limit - b.b.Len()
		if remaining > 0 {
			_, _ = b.b.Write(p[:remaining])
		}
		b.exceeded = true
		return len(p), nil
	}
	return b.b.Write(p)
}
func (b *limitedBuffer) Bytes() []byte { return append([]byte(nil), b.b.Bytes()...) }

var _ io.Writer = (*limitedBuffer)(nil)
