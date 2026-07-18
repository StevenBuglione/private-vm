package qemu

import (
	"path/filepath"
	"testing"
)

func validSpec(t *testing.T) Spec {
	t.Helper()
	dir := t.TempDir()
	return Spec{
		Binary:       "/usr/bin/qemu-system-x86_64",
		SessionID:    "s1",
		Name:         "private-vm-s1",
		CPUs:         4,
		MemoryBytes:  4 << 30,
		Root:         Disk{Path: filepath.Join(dir, "root.qcow2"), Format: "qcow2", Serial: "root"},
		QMPSocket:    filepath.Join(dir, "qmp.sock"),
		SPICESocket:  filepath.Join(dir, "spice.sock"),
		VSOCKCID:     42,
		Networked:    false,
		FWCfgTokenFD: 3,
	}
}

func TestOfflineArgsHaveNoNIC(t *testing.T) {
	spec := validSpec(t)
	args, err := spec.Args()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range args {
		if args[i] == "-nic" && i+1 < len(args) && args[i+1] == "none" {
			found = true
		}
	}
	if !found {
		t.Fatal("offline spec did not disable NIC")
	}
	if err := ValidateNoTCPListener(args); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsRelativeBinary(t *testing.T) {
	spec := validSpec(t)
	spec.Binary = "qemu"
	if err := spec.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}
