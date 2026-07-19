//go:build linux

package scan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestArchiveInspectionRejectsTraversalLinksEncryptionAndBombs(t *testing.T) {
	limits := testArchiveLimits()

	traversal := buildZIP(t, []zipFixture{{name: "../escape", body: "x"}})
	if _, err := InspectZIP(t.Context(), bytes.NewReader(traversal), int64(len(traversal)), 0, limits); ErrorCode(err) != "ARCHIVE_PATH_UNSAFE" {
		t.Fatalf("ZIP traversal error = %v", err)
	}

	symlinkHeader := &zip.FileHeader{Name: "link", Method: zip.Store}
	symlinkHeader.SetMode(os.ModeSymlink | 0o777)
	symlink := buildZIP(t, []zipFixture{{header: symlinkHeader, body: "../escape"}})
	if _, err := InspectZIP(t.Context(), bytes.NewReader(symlink), int64(len(symlink)), 0, limits); ErrorCode(err) != "ARCHIVE_LINK_REJECTED" {
		t.Fatalf("ZIP symlink error = %v", err)
	}

	encrypted := markZIPEncrypted(t, buildZIP(t, []zipFixture{{name: "file", body: "x"}}))
	if _, err := InspectZIP(t.Context(), bytes.NewReader(encrypted), int64(len(encrypted)), 0, limits); ErrorCode(err) != "ARCHIVE_ENCRYPTED" {
		t.Fatalf("encrypted ZIP error = %v", err)
	}

	bomb := buildZIP(t, []zipFixture{{name: "large", body: string(bytes.Repeat([]byte("A"), 64<<10))}})
	bombLimits := limits
	bombLimits.MaxExpansionRatio = 2
	if _, err := InspectZIP(t.Context(), bytes.NewReader(bomb), int64(len(bomb)), 0, bombLimits); ErrorCode(err) != "ARCHIVE_LIMIT_REACHED" {
		t.Fatalf("ZIP ratio error = %v", err)
	}

	if _, err := InspectZIP(t.Context(), bytes.NewReader(bomb), int64(len(bomb)), limits.MaxDepth+1, limits); ErrorCode(err) != "ARCHIVE_LIMIT_REACHED" {
		t.Fatalf("nested depth error = %v", err)
	}
}

func TestTARInspectionRejectsAbsoluteHardlinkAndSpecial(t *testing.T) {
	limits := testArchiveLimits()
	for _, test := range []struct {
		name   string
		header *tar.Header
		code   string
	}{
		{"absolute", &tar.Header{Name: "/escape", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}, "ARCHIVE_PATH_UNSAFE"},
		{"hardlink", &tar.Header{Name: "link", Linkname: "target", Typeflag: tar.TypeLink}, "ARCHIVE_LINK_REJECTED"},
		{"fifo", &tar.Header{Name: "pipe", Typeflag: tar.TypeFifo}, "ARCHIVE_SPECIAL_FILE_REJECTED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			archive := buildTAR(t, test.header, []byte("x"))
			_, err := InspectTAR(t.Context(), bytes.NewReader(archive), uint64(len(archive)), 0, limits)
			if ErrorCode(err) != test.code {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestZIPAndTARExtractionAreBoundedInventoriedAndCleaned(t *testing.T) {
	sandboxRoot := runtimeTmpfs(t)
	sandbox := ExtractionSandbox{
		ParentPath: sandboxRoot, Tmpfs: true, PrivateMountNamespace: true,
		WorkerUID: os.Geteuid(), WorkerGID: os.Getegid(),
	}
	limits := testArchiveLimits()

	zipBytes := buildZIP(t, []zipFixture{{name: "nested/file.txt", body: "safe text"}})
	extraction, err := ExtractZIP(t.Context(), bytes.NewReader(zipBytes), int64(len(zipBytes)), 0, limits, sandbox, ConservativeMIMEClassifier{})
	if err != nil {
		t.Fatal(err)
	}
	if len(extraction.Manifest().Entries) != 1 || extraction.Manifest().Entries[0].RelativePath != "nested/file.txt" {
		t.Fatalf("ZIP manifest = %+v", extraction.Manifest())
	}
	path := extraction.RootPath()
	if err := extraction.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := extraction.Cleanup(); err != nil {
		t.Fatalf("idempotent cleanup: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("extraction remains after cleanup: %v", err)
	}

	tarBytes := buildTAR(t, &tar.Header{Name: "file.txt", Mode: 0o600, Size: 4, Typeflag: tar.TypeReg}, []byte("safe"))
	tarExtraction, err := ExtractTAR(t.Context(), bytes.NewReader(tarBytes), uint64(len(tarBytes)), 0, limits, sandbox, ConservativeMIMEClassifier{})
	if err != nil {
		t.Fatal(err)
	}
	if tarExtraction.Manifest().TotalBytes != 4 {
		t.Fatalf("TAR manifest = %+v", tarExtraction.Manifest())
	}
	if err := tarExtraction.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractionCancellationFailureAndIdentitySafeCleanup(t *testing.T) {
	sandboxRoot := runtimeTmpfs(t)
	sandbox := ExtractionSandbox{ParentPath: sandboxRoot, Tmpfs: true, PrivateMountNamespace: true, WorkerUID: os.Geteuid(), WorkerGID: os.Getegid()}
	archive := buildZIP(t, []zipFixture{{name: "file", body: "body"}})

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ExtractZIP(cancelled, bytes.NewReader(archive), int64(len(archive)), 0, testArchiveLimits(), sandbox, ConservativeMIMEClassifier{}); ErrorCode(err) != "SCAN_CANCELLED" {
		t.Fatalf("cancellation error = %v", err)
	}
	entries, err := os.ReadDir(sandboxRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancellation left extraction entries: %v, %v", entries, err)
	}

	extraction, err := ExtractZIP(t.Context(), bytes.NewReader(archive), int64(len(archive)), 0, testArchiveLimits(), sandbox, ConservativeMIMEClassifier{})
	if err != nil {
		t.Fatal(err)
	}
	original := extraction.RootPath()
	moved := original + "-moved"
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := extraction.Cleanup(); ErrorCode(err) != "ARCHIVE_CLEANUP_INCOMPLETE" {
		t.Fatalf("replacement cleanup error = %v", err)
	}
	if _, err := os.Stat(original); err != nil {
		t.Fatal("cleanup removed substituted directory")
	}
	if err := os.RemoveAll(original); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(moved); err != nil {
		t.Fatal(err)
	}
}

type zipFixture struct {
	name   string
	header *zip.FileHeader
	body   string
}

func buildZIP(t *testing.T, fixtures []zipFixture) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, fixture := range fixtures {
		header := fixture.header
		if header == nil {
			header = &zip.FileHeader{Name: fixture.name, Method: zip.Deflate}
			header.SetMode(0o600)
		}
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(fixture.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func markZIPEncrypted(t *testing.T, archive []byte) []byte {
	t.Helper()
	result := append([]byte(nil), archive...)
	local := bytes.Index(result, []byte("PK\x03\x04"))
	central := bytes.Index(result, []byte("PK\x01\x02"))
	if local < 0 || central < 0 {
		t.Fatal("ZIP headers missing")
	}
	result[local+6] |= 1
	result[central+8] |= 1
	return result
}

func buildTAR(t *testing.T, header *tar.Header, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if header.Size > 0 {
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func runtimeTmpfs(t *testing.T) string {
	t.Helper()
	parent := filepath.Join("/run/user", strconv.Itoa(os.Geteuid()))
	root, err := os.MkdirTemp(parent, "private-vm-scan-test-")
	if err != nil {
		t.Skipf("tmpfs test root unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func testArchiveLimits() ArchiveLimits {
	return ArchiveLimits{
		MaxDepth: 3, MaxEntries: 32, MaxPathBytes: 512,
		MaxFileBytes: 1 << 20, MaxExpandedBytes: 2 << 20, MaxExpansionRatio: 1000,
	}
}
