package main

import (
	"bytes"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"version", "--json"}, &stdout, &stderr)
	if code != exitcode.OK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("expected output")
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"nope"}, &stdout, &stderr)
	if code != exitcode.Usage {
		t.Fatalf("code=%d", code)
	}
}
