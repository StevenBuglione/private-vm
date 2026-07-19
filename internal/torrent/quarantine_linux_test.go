//go:build linux

package torrent

import (
	"os"
	"testing"
)

func TestInspectQuarantineFormatAcceptsOnlyBlankOrExt4(t *testing.T) {
	for name, test := range map[string]struct {
		mutate  func([]byte)
		want    quarantineFormatState
		wantErr bool
	}{
		"blank":   {want: quarantineBlank},
		"ext4":    {mutate: func(value []byte) { value[1080], value[1081] = 0x53, 0xef }, want: quarantineExt4},
		"unknown": {mutate: func(value []byte) { value[7] = 1 }, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			value := make([]byte, 4096)
			if test.mutate != nil {
				test.mutate(value)
			}
			path := t.TempDir() + "/device"
			if err := os.WriteFile(path, value, 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := inspectQuarantineFormat(file)
			_ = file.Close()
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("inspect=%d err=%v", got, err)
			}
		})
	}
}

func TestParseQuarantineMountEvidenceFailsClosed(t *testing.T) {
	valid := []byte("42 1 253:7 / /mnt/quarantine rw,nosuid,nodev,noexec - ext4 /dev/vdb rw\n")
	mounted, err := parseQuarantineMountEvidence(valid, 253, 7, "/mnt/quarantine")
	if err != nil || !mounted {
		t.Fatalf("valid mount evidence: mounted=%v err=%v", mounted, err)
	}

	for name, raw := range map[string][]byte{
		"device elsewhere": []byte("42 1 253:7 / /mnt/other rw,nosuid,nodev,noexec - ext4 /dev/vdb rw\n"),
		"target occupied":  []byte("42 1 253:8 / /mnt/quarantine rw,nosuid,nodev,noexec - ext4 /dev/vdc rw\n"),
		"missing noexec":   []byte("42 1 253:7 / /mnt/quarantine rw,nosuid,nodev - ext4 /dev/vdb rw\n"),
		"wrong filesystem": []byte("42 1 253:7 / /mnt/quarantine rw,nosuid,nodev,noexec - xfs /dev/vdb rw\n"),
	} {
		t.Run(name, func(t *testing.T) {
			mounted, err := parseQuarantineMountEvidence(raw, 253, 7, "/mnt/quarantine")
			if err == nil || mounted {
				t.Fatalf("unsafe evidence accepted: mounted=%v err=%v", mounted, err)
			}
		})
	}
}
