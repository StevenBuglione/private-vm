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

func TestDocumentedCommandSurface(t *testing.T) {
	root := newRootCommand(&globalOptions{}, &bytes.Buffer{}, &bytes.Buffer{})
	for _, name := range []string{"init", "plan", "desktop", "workspace", "torrent", "scan", "vpn", "usb", "images", "session", "policy", "config", "system", "run", "completion"} {
		if command, _, err := root.Find([]string{name}); err != nil || command == root {
			t.Fatalf("missing command %s: %v", name, err)
		}
	}
}

func TestMagnetArgvFlagDoesNotExist(t *testing.T) {
	root := newRootCommand(&globalOptions{}, &bytes.Buffer{}, &bytes.Buffer{})
	command, _, err := root.Find([]string{"torrent", "add"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Flags().Lookup("magnet") != nil {
		t.Fatal("magnet argv flag must not exist")
	}
}
