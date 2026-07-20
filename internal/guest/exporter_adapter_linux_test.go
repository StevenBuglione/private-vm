//go:build linux

package guest

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/transfer"
)

type exporterCommandCall struct {
	path  string
	args  []string
	stdin []byte
}

type exporterRunnerFixture struct{ calls []exporterCommandCall }

func (runner *exporterRunnerFixture) Run(_ context.Context, stdin io.Reader, path string, args ...string) error {
	var input []byte
	if stdin != nil {
		input, _ = io.ReadAll(stdin)
	}
	runner.calls = append(runner.calls, exporterCommandCall{path: path, args: append([]string(nil), args...), stdin: input})
	return nil
}

func fixedExporterTestPaths(t *testing.T) fixedExporterPaths {
	t.Helper()
	root := t.TempDir()
	mount := filepath.Join(root, "run", "private-vm", "export")
	if err := os.MkdirAll(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	return fixedExporterPaths{
		USBRoot: filepath.Join(root, "sys", "usb"), BlockRoot: filepath.Join(root, "sys", "block"), DeviceRoot: filepath.Join(root, "dev"),
		NetworkRoot: filepath.Join(root, "sys", "net"), MountInfo: filepath.Join(root, "mountinfo"), MountPoint: mount,
		MapperPath: filepath.Join(root, "dev", "mapper", fixedExporterMapperName), Cryptsetup: filepath.Join(root, "bin", "cryptsetup"),
		MkfsExt4: filepath.Join(root, "bin", "mkfs.ext4"), Mount: filepath.Join(root, "bin", "mount"), Umount: filepath.Join(root, "bin", "umount"),
		Wipefs: filepath.Join(root, "bin", "wipefs"), Blkid: filepath.Join(root, "bin", "blkid"),
	}
}

func TestFixedExporterPrepareUsesOnlyFixedArgumentsAndSecretStdin(t *testing.T) {
	runner := &exporterRunnerFixture{}
	adapter, err := newFixedExporterAdapter(fixedExporterTestPaths(t), runner)
	if err != nil {
		t.Fatal(err)
	}
	adapter.filesystemVerifier = func(string) error { return nil }
	adapter.device = filepath.Join(adapter.paths.DeviceRoot, "sda")
	passphraseBytes := []byte("private-test-passphrase")
	passphrase, err := secret.New(passphraseBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(passphrase.Destroy)
	evidence, err := adapter.Prepare(t.Context(), passphrase)
	if err != nil || !evidence.IdentityVerified || !evidence.LUKS2 || !evidence.Ext4 || !evidence.Mounted {
		t.Fatalf("evidence=%#v err=%v", evidence, err)
	}
	if len(runner.calls) != 6 {
		t.Fatalf("calls=%#v", runner.calls)
	}
	secretCalls := 0
	for _, call := range runner.calls {
		joined := strings.Join(call.args, " ")
		if strings.Contains(joined, string(passphraseBytes)) {
			t.Fatal("passphrase reached command arguments")
		}
		if len(call.stdin) > 0 {
			secretCalls++
			if !slices.Equal(call.stdin, passphraseBytes) {
				t.Fatal("unexpected command stdin")
			}
		}
	}
	if secretCalls != 2 {
		t.Fatalf("secret stdin calls=%d", secretCalls)
	}
}

func TestFixedExporterWriterCommitsRereadsAndAbortsAtFixedNames(t *testing.T) {
	adapter, err := newFixedExporterAdapter(fixedExporterTestPaths(t), &exporterRunnerFixture{})
	if err != nil {
		t.Fatal(err)
	}
	adapter.mounted = true
	data := []byte("approved reconstructed output")
	digest := sha256.Sum256(data)
	writer, err := adapter.BeginWrite(t.Context(), transfer.Header{Name: "ignored-user-name", Size: uint64(len(data)), SHA256: digest, MediaType: "application/octet-stream"}, "transfer-12345678")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteChunk(t.Context(), 0, data); err != nil {
		t.Fatal(err)
	}
	evidence, err := writer.Commit(t.Context(), uint64(len(data)), digest)
	if err != nil || !evidence.FileSynced || !evidence.FilesystemSynced || !evidence.AtomicRename || evidence.ReceiverDigest != digest {
		t.Fatalf("evidence=%#v err=%v", evidence, err)
	}
	if _, err := os.Stat(filepath.Join(adapter.paths.MountPoint, "ignored-user-name")); !os.IsNotExist(err) {
		t.Fatal("caller-controlled filename reached destination")
	}
	reread, err := adapter.Reread(t.Context(), "transfer-12345678")
	if err != nil || reread != digest {
		t.Fatalf("reread=%x err=%v", reread, err)
	}

	abortAdapter, err := newFixedExporterAdapter(fixedExporterTestPaths(t), &exporterRunnerFixture{})
	if err != nil {
		t.Fatal(err)
	}
	abortAdapter.mounted = true
	aborted, err := abortAdapter.BeginWrite(t.Context(), transfer.Header{Size: 1}, "transfer-abcdef12")
	if err != nil {
		t.Fatal(err)
	}
	if err := aborted.WriteChunk(t.Context(), 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := aborted.Abort(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(abortAdapter.paths.MountPoint, fixedExporterTempName)); !os.IsNotExist(err) {
		t.Fatal("partial exporter file survived abort")
	}
}
