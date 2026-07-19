package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

func TestRunDelegatesToCLI(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"version", "--json"}, &stdout, &stderr)
	if code != exitcode.OK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunPropagatesCancelledProcessContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"init"}, &stdout, &stderr); code != exitcode.Cancelled {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
