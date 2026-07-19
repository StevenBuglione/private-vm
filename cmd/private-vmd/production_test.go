package main

import (
	"context"
	"errors"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/storage"
)

type versionRunner struct {
	output []byte
	err    error
}

func (runner versionRunner) Run(context.Context, storage.Command) (storage.Result, error) {
	return storage.Result{Stdout: append([]byte(nil), runner.output...)}, runner.err
}

func TestProbeQEMUVersionAcceptsOnlyBoundedSemanticVersion(t *testing.T) {
	got, err := probeQEMUVersion(t.Context(), versionRunner{output: []byte("QEMU emulator version 10.2.4\n")}, "/trusted/qemu")
	if err != nil || got != "10.2.4" {
		t.Fatalf("version = %q, %v", got, err)
	}
	for _, runner := range []versionRunner{
		{output: []byte("unrecognized\n")},
		{err: errors.New("failed")},
	} {
		if _, err := probeQEMUVersion(t.Context(), runner, "/trusted/qemu"); err == nil {
			t.Fatal("unsafe version response was accepted")
		}
	}
}
