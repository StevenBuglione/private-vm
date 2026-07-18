package commandexec

import (
	"context"
	"fmt"
	"os/exec"
)

type Result struct {
	Stdout []byte
	Stderr []byte
}

type Executor interface {
	Run(ctx context.Context, absolutePath string, args ...string) (Result, error)
}

type OSExecutor struct{}

func (OSExecutor) Run(ctx context.Context, absolutePath string, args ...string) (Result, error) {
	if len(absolutePath) == 0 || absolutePath[0] != '/' {
		return Result{}, fmt.Errorf("executable path must be absolute")
	}
	cmd := exec.CommandContext(ctx, absolutePath, args...)
	var stdout, stderr bytesBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, err
}

// bytesBuffer is intentionally tiny to keep the starter dependency-free.
// Production code must add bounded capture or streaming to avoid unbounded memory.
type bytesBuffer struct{ b []byte }

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.b = append(b.b, p...)
	return len(p), nil
}
func (b *bytesBuffer) Bytes() []byte { return append([]byte(nil), b.b...) }
