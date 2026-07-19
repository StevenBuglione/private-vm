package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCommandRejectsUnknownOperation(t *testing.T) {
	err := run(context.Background(), []string{"shell"}, strings.NewReader("secret"), new(bytes.Buffer))
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublishRequiresTokenStdinFlag(t *testing.T) {
	err := run(context.Background(), []string{"publish"}, strings.NewReader("must-not-be-read"), new(bytes.Buffer))
	if err == nil || !strings.Contains(err.Error(), "--token-stdin") || strings.Contains(err.Error(), "must-not-be-read") {
		t.Fatalf("unexpected safe error: %v", err)
	}
}

func TestPublishRejectsMultilineCredentialWithoutDisclosure(t *testing.T) {
	credential := "private-first-line\nprivate-second-line"
	err := run(context.Background(), []string{
		"publish", "--token-stdin", "--prepared", "/tmp/prepared", "--provenance", "/tmp/provenance",
		"--repository", "ghcr.io/stevenbuglione/private-vm/scanner", "--tag", "v1.2.3", "--username", "actor",
	}, strings.NewReader(credential), new(bytes.Buffer))
	if err == nil || strings.Contains(err.Error(), "private-first-line") || strings.Contains(err.Error(), "private-second-line") {
		t.Fatalf("credential leaked in error: %v", err)
	}
}
