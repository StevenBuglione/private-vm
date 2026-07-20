package scan

import (
	"archive/tar"
	"archive/zip"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
)

type ArchiveFormat string

const (
	ArchiveZIP ArchiveFormat = "zip"
	ArchiveTAR ArchiveFormat = "tar"
)

type ArchiveLimits struct {
	MaxDepth          uint32
	MaxEntries        uint64
	MaxPathBytes      int
	MaxFileBytes      uint64
	MaxExpandedBytes  uint64
	MaxExpansionRatio float64
}

type ArchiveEntry struct {
	RelativePath    string
	Directory       bool
	SizeBytes       uint64
	CompressedBytes uint64
}

type ArchivePlan struct {
	Format          ArchiveFormat
	Depth           uint32
	Entries         []ArchiveEntry
	ExpandedBytes   uint64
	CompressedBytes uint64
}

func InspectZIP(ctx context.Context, reader io.ReaderAt, archiveBytes int64, depth uint32, limits ArchiveLimits) (ArchivePlan, error) {
	limits, err := validateArchiveLimits(limits, depth)
	if err != nil {
		return ArchivePlan{}, err
	}
	if reader == nil || archiveBytes < 0 || uint64(archiveBytes) > limits.MaxFileBytes {
		return ArchivePlan{}, scanError("ARCHIVE_LIMIT_REACHED", "A ZIP archive exceeds its bounded input size.", "Reduce the selected content and restart the workflow.", nil)
	}
	archive, err := zip.NewReader(reader, archiveBytes)
	if err != nil {
		return ArchivePlan{}, scanError("ARCHIVE_INVALID", "A ZIP archive could not be parsed completely.", "Reject this archive; malformed content is never promoted.", err)
	}
	plan := ArchivePlan{Format: ArchiveZIP, Depth: depth, Entries: make([]ArchiveEntry, 0, len(archive.File))}
	seen := make(map[string]struct{}, len(archive.File))
	for _, file := range archive.File {
		if err := ctx.Err(); err != nil {
			return ArchivePlan{}, contextScanError(err)
		}
		if file.Flags&1 != 0 {
			return ArchivePlan{}, scanError("ARCHIVE_ENCRYPTED", "An encrypted ZIP member cannot be inspected.", "Reject encrypted archives under the safe policy.", nil)
		}
		mode := file.Mode()
		if mode&os.ModeSymlink != 0 {
			return ArchivePlan{}, scanError("ARCHIVE_LINK_REJECTED", "A ZIP archive contains a symbolic link.", "Reject archives containing links under the safe policy.", nil)
		}
		if !mode.IsRegular() && !mode.IsDir() {
			return ArchivePlan{}, scanError("ARCHIVE_SPECIAL_FILE_REJECTED", "A ZIP archive contains a non-regular entry.", "Reject archives containing devices, sockets or FIFOs.", nil)
		}
		entry, err := addArchiveEntry(&plan, seen, file.Name, mode.IsDir(), file.UncompressedSize64, file.CompressedSize64, limits)
		if err != nil {
			return ArchivePlan{}, err
		}
		plan.Entries = append(plan.Entries, entry)
	}
	if err := validateExpansion(plan, limits); err != nil {
		return ArchivePlan{}, err
	}
	return plan, nil
}

func InspectTAR(ctx context.Context, reader io.Reader, archiveBytes uint64, depth uint32, limits ArchiveLimits) (ArchivePlan, error) {
	limits, err := validateArchiveLimits(limits, depth)
	if err != nil {
		return ArchivePlan{}, err
	}
	if reader == nil || archiveBytes > limits.MaxFileBytes {
		return ArchivePlan{}, scanError("ARCHIVE_LIMIT_REACHED", "A TAR archive exceeds its bounded input size.", "Reduce the selected content and restart the workflow.", nil)
	}
	plan := ArchivePlan{Format: ArchiveTAR, Depth: depth, CompressedBytes: archiveBytes}
	seen := make(map[string]struct{})
	tarReader := tar.NewReader(&contextReader{ctx: ctx, reader: io.LimitReader(reader, int64(archiveBytes)+1)})
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return ArchivePlan{}, contextScanError(ctx.Err())
			}
			return ArchivePlan{}, scanError("ARCHIVE_INVALID", "A TAR archive could not be parsed completely.", "Reject this archive; malformed content is never promoted.", err)
		}
		if header.Size < 0 {
			return ArchivePlan{}, scanError("ARCHIVE_INVALID", "A TAR member has an invalid declared size.", "Reject this archive; malformed content is never promoted.", nil)
		}
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			return ArchivePlan{}, scanError("ARCHIVE_LINK_REJECTED", "A TAR archive contains a symbolic or hard link.", "Reject archives containing links under the safe policy.", nil)
		}
		directory := header.Typeflag == tar.TypeDir
		if header.Typeflag != tar.TypeReg && !directory {
			return ArchivePlan{}, scanError("ARCHIVE_SPECIAL_FILE_REJECTED", "A TAR archive contains a non-regular entry.", "Reject archives containing devices, sockets or FIFOs.", nil)
		}
		entry, err := addArchiveEntry(&plan, seen, header.Name, directory, uint64(header.Size), 0, limits)
		if err != nil {
			return ArchivePlan{}, err
		}
		plan.Entries = append(plan.Entries, entry)
	}
	if err := validateExpansion(plan, limits); err != nil {
		return ArchivePlan{}, err
	}
	return plan, nil
}

func validateArchiveLimits(limits ArchiveLimits, depth uint32) (ArchiveLimits, error) {
	if limits.MaxDepth > 10 || depth > limits.MaxDepth {
		return ArchiveLimits{}, scanError("ARCHIVE_LIMIT_REACHED", "Nested archive depth exceeds the configured limit.", "Reduce archive nesting and restart the workflow.", nil)
	}
	if limits.MaxEntries == 0 || limits.MaxEntries > 1_000_000 || limits.MaxFileBytes == 0 || limits.MaxFileBytes > 1<<40 ||
		limits.MaxExpandedBytes == 0 || limits.MaxExpandedBytes > 4<<40 || limits.MaxExpansionRatio < 1 || limits.MaxExpansionRatio > 1000 {
		return ArchiveLimits{}, scanError("SCAN_LIMIT_INVALID", "Archive limits are outside supported bounds.", "Use the finite count, size, depth and ratio limits from the validated scan policy.", nil)
	}
	if limits.MaxPathBytes == 0 {
		limits.MaxPathBytes = MaximumInventoryPathBytes
	}
	if limits.MaxPathBytes < 64 || limits.MaxPathBytes > MaximumInventoryPathBytes {
		return ArchiveLimits{}, scanError("SCAN_LIMIT_INVALID", "The archive path limit is outside supported bounds.", "Use a path limit from 64 through 4096 bytes.", nil)
	}
	return limits, nil
}

func addArchiveEntry(plan *ArchivePlan, seen map[string]struct{}, name string, directory bool, size, compressed uint64, limits ArchiveLimits) (ArchiveEntry, error) {
	normalized, err := validateArchivePath(name, directory, limits.MaxPathBytes)
	if err != nil {
		return ArchiveEntry{}, err
	}
	if _, exists := seen[normalized]; exists {
		return ArchiveEntry{}, scanError("ARCHIVE_DUPLICATE_PATH", "An archive contains duplicate output paths.", "Reject ambiguous archives under the safe policy.", nil)
	}
	seen[normalized] = struct{}{}
	if uint64(len(plan.Entries)) >= limits.MaxEntries || size > limits.MaxFileBytes || size > limits.MaxExpandedBytes-plan.ExpandedBytes {
		return ArchiveEntry{}, scanError("ARCHIVE_LIMIT_REACHED", "Archive content exceeds a configured count or size limit.", "Reduce archive size or entry count and restart the workflow.", nil)
	}
	if compressed > ^uint64(0)-plan.CompressedBytes {
		return ArchiveEntry{}, scanError("ARCHIVE_LIMIT_REACHED", "Archive size accounting overflowed.", "Reject this malformed archive.", nil)
	}
	plan.ExpandedBytes += size
	plan.CompressedBytes += compressed
	return ArchiveEntry{RelativePath: normalized, Directory: directory, SizeBytes: size, CompressedBytes: compressed}, nil
}

func validateExpansion(plan ArchivePlan, limits ArchiveLimits) error {
	if plan.ExpandedBytes > limits.MaxExpandedBytes {
		return scanError("ARCHIVE_LIMIT_REACHED", "Archive expanded size exceeds policy.", "Reduce archive content and restart the workflow.", nil)
	}
	if plan.ExpandedBytes > 0 && plan.CompressedBytes == 0 && plan.Format == ArchiveZIP {
		return scanError("ARCHIVE_LIMIT_REACHED", "Archive expansion ratio cannot be bounded.", "Reject this malformed archive.", nil)
	}
	if plan.CompressedBytes > 0 && float64(plan.ExpandedBytes)/float64(plan.CompressedBytes) > limits.MaxExpansionRatio {
		return scanError("ARCHIVE_LIMIT_REACHED", "Archive expansion ratio exceeds policy.", "Reduce compression or expanded content and restart the workflow.", nil)
	}
	return nil
}

func validateArchivePath(value string, directory bool, maximum int) (string, error) {
	if !utf8.ValidString(value) || value == "" || len(value) > maximum || strings.ContainsAny(value, "\x00\\") || strings.HasPrefix(value, "/") {
		return "", scanError("ARCHIVE_PATH_UNSAFE", "An archive entry path is unsafe.", "Reject archives containing absolute, invalid or oversized paths.", nil)
	}
	trimmed := strings.TrimSuffix(value, "/")
	if trimmed == "" || path.Clean(trimmed) != trimmed {
		return "", scanError("ARCHIVE_PATH_UNSAFE", "An archive entry path is unsafe.", "Reject archives containing traversal or ambiguous paths.", nil)
	}
	for _, component := range strings.Split(trimmed, "/") {
		if component == "" || component == "." || component == ".." || strings.Contains(component, ":") {
			return "", scanError("ARCHIVE_PATH_UNSAFE", "An archive entry path is unsafe.", "Reject archives containing traversal or platform-absolute paths.", nil)
		}
	}
	if directory {
		return trimmed, nil
	}
	return trimmed, nil
}

type ExtractionSandbox struct {
	ParentPath            string
	Tmpfs                 bool
	PrivateMountNamespace bool
	WorkerUID             int
	WorkerGID             int
}

type Extraction struct {
	mu       sync.Mutex
	parent   *os.Root
	name     string
	path     string
	identity fileInfoIdentity
	cleaned  bool
	manifest Inventory
}

type fileInfoIdentity struct {
	mode   os.FileMode
	native any
}

func (extraction *Extraction) RootPath() string {
	if extraction == nil {
		return ""
	}
	return extraction.path
}

func (extraction *Extraction) Manifest() Inventory {
	if extraction == nil {
		return Inventory{}
	}
	copy := extraction.manifest
	copy.Entries = append([]InventoryEntry(nil), extraction.manifest.Entries...)
	return copy
}

func (extraction *Extraction) Cleanup() error {
	if extraction == nil {
		return nil
	}
	extraction.mu.Lock()
	defer extraction.mu.Unlock()
	if extraction.cleaned {
		return nil
	}
	info, err := extraction.parent.Lstat(extraction.name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			extraction.cleaned = true
			return extraction.parent.Close()
		}
		return scanError("ARCHIVE_CLEANUP_INCOMPLETE", "The archive extraction directory could not be revalidated.", "Destroy the scanner so volatile storage cleanup can retry.", err)
	}
	if !info.IsDir() || !sameFileInfoIdentity(info, extraction.identity) {
		return scanError("ARCHIVE_CLEANUP_INCOMPLETE", "The archive extraction directory identity changed.", "Destroy the scanner; the cleanup owner will preserve and report the substituted path.", nil)
	}
	if err := extraction.parent.RemoveAll(extraction.name); err != nil {
		return scanError("ARCHIVE_CLEANUP_INCOMPLETE", "The archive extraction directory could not be removed.", "Destroy the scanner so volatile storage cleanup can retry.", err)
	}
	extraction.cleaned = true
	return extraction.parent.Close()
}

func ExtractZIP(ctx context.Context, reader io.ReaderAt, archiveBytes int64, depth uint32, limits ArchiveLimits, sandbox ExtractionSandbox, classifier MIMEClassifier) (*Extraction, error) {
	plan, err := InspectZIP(ctx, reader, archiveBytes, depth, limits)
	if err != nil {
		return nil, err
	}
	archive, err := zip.NewReader(reader, archiveBytes)
	if err != nil {
		return nil, scanError("ARCHIVE_INVALID", "The ZIP archive changed between inspection and extraction.", "Reject this archive and repeat the download in a fresh session.", err)
	}
	extraction, root, err := beginExtraction(sandbox)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*Extraction, error) {
		_ = root.Close()
		cleanupErr := extraction.Cleanup()
		if cleanupErr != nil {
			return nil, cleanupErr
		}
		return nil, cause
	}
	for index, file := range archive.File {
		if err := ctx.Err(); err != nil {
			return fail(contextScanError(err))
		}
		entry := plan.Entries[index]
		if entry.Directory {
			if err := root.MkdirAll(entry.RelativePath, 0o700); err != nil {
				return fail(extractionError(err))
			}
			continue
		}
		if parent := path.Dir(entry.RelativePath); parent != "." {
			if err := root.MkdirAll(parent, 0o700); err != nil {
				return fail(extractionError(err))
			}
		}
		source, err := file.Open()
		if err != nil {
			return fail(extractionError(err))
		}
		destination, err := root.OpenFile(entry.RelativePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			source.Close()
			return fail(extractionError(err))
		}
		written, copyErr := copyExact(ctx, destination, source, entry.SizeBytes)
		closeDestinationErr := destination.Close()
		closeSourceErr := source.Close()
		if copyErr != nil || closeDestinationErr != nil || closeSourceErr != nil || written != entry.SizeBytes {
			if ctx.Err() != nil {
				return fail(contextScanError(ctx.Err()))
			}
			return fail(extractionError(errors.Join(copyErr, closeDestinationErr, closeSourceErr)))
		}
	}
	if err := root.Close(); err != nil {
		return fail(extractionError(err))
	}
	manifest, err := BuildInventory(ctx, extraction.path, InventoryLimits{MaxFiles: limits.MaxEntries, MaxInputBytes: limits.MaxExpandedBytes, MaxPathBytes: limits.MaxPathBytes}, classifier)
	if err != nil {
		return fail(err)
	}
	if manifest.TotalBytes != plan.ExpandedBytes || uint64(len(manifest.Entries)) > limits.MaxEntries {
		return fail(scanError("ARCHIVE_LIMIT_REACHED", "Extracted archive content does not match its bounded manifest.", "Reject this archive; incomplete extraction is never promoted.", nil))
	}
	extraction.manifest = manifest
	return extraction, nil
}

func ExtractTAR(ctx context.Context, reader io.ReadSeeker, archiveBytes uint64, depth uint32, limits ArchiveLimits, sandbox ExtractionSandbox, classifier MIMEClassifier) (*Extraction, error) {
	if reader == nil {
		return nil, scanError("ARCHIVE_INVALID", "The TAR archive input is unavailable.", "Reject this archive and repeat the download in a fresh session.", nil)
	}
	plan, err := InspectTAR(ctx, reader, archiveBytes, depth, limits)
	if err != nil {
		return nil, err
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return nil, scanError("ARCHIVE_INVALID", "The TAR archive could not be rewound after inspection.", "Reject this archive and repeat the download in a fresh session.", err)
	}
	extraction, root, err := beginExtraction(sandbox)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*Extraction, error) {
		_ = root.Close()
		if cleanupErr := extraction.Cleanup(); cleanupErr != nil {
			return nil, cleanupErr
		}
		return nil, cause
	}
	tarReader := tar.NewReader(&contextReader{ctx: ctx, reader: io.LimitReader(reader, int64(archiveBytes)+1)})
	entryIndex := 0
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || entryIndex >= len(plan.Entries) {
			if ctx.Err() != nil {
				return fail(contextScanError(ctx.Err()))
			}
			return fail(scanError("ARCHIVE_INVALID", "The TAR archive changed between inspection and extraction.", "Reject this archive and repeat the download in a fresh session.", err))
		}
		entry := plan.Entries[entryIndex]
		entryIndex++
		if header.Name != entry.RelativePath && strings.TrimSuffix(header.Name, "/") != entry.RelativePath {
			return fail(scanError("ARCHIVE_INVALID", "The TAR archive manifest changed before extraction.", "Reject this archive and repeat the download in a fresh session.", nil))
		}
		if entry.Directory {
			if err := root.MkdirAll(entry.RelativePath, 0o700); err != nil {
				return fail(extractionError(err))
			}
			continue
		}
		if parent := path.Dir(entry.RelativePath); parent != "." {
			if err := root.MkdirAll(parent, 0o700); err != nil {
				return fail(extractionError(err))
			}
		}
		destination, err := root.OpenFile(entry.RelativePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fail(extractionError(err))
		}
		written, copyErr := copyExact(ctx, destination, tarReader, entry.SizeBytes)
		closeErr := destination.Close()
		if copyErr != nil || closeErr != nil || written != entry.SizeBytes {
			if ctx.Err() != nil {
				return fail(contextScanError(ctx.Err()))
			}
			return fail(extractionError(errors.Join(copyErr, closeErr)))
		}
	}
	if entryIndex != len(plan.Entries) {
		return fail(scanError("ARCHIVE_INVALID", "The TAR extraction manifest is incomplete.", "Reject this archive and repeat the download in a fresh session.", nil))
	}
	if err := root.Close(); err != nil {
		return fail(extractionError(err))
	}
	manifest, err := BuildInventory(ctx, extraction.path, InventoryLimits{MaxFiles: limits.MaxEntries, MaxInputBytes: limits.MaxExpandedBytes, MaxPathBytes: limits.MaxPathBytes}, classifier)
	if err != nil {
		return fail(err)
	}
	if manifest.TotalBytes != plan.ExpandedBytes || uint64(len(manifest.Entries)) > limits.MaxEntries {
		return fail(scanError("ARCHIVE_LIMIT_REACHED", "Extracted archive content does not match its bounded manifest.", "Reject this archive; incomplete extraction is never promoted.", nil))
	}
	extraction.manifest = manifest
	return extraction, nil
}

func beginExtraction(sandbox ExtractionSandbox) (*Extraction, *os.Root, error) {
	if !filepath.IsAbs(sandbox.ParentPath) || filepath.Clean(sandbox.ParentPath) != sandbox.ParentPath ||
		!sandbox.Tmpfs || !sandbox.PrivateMountNamespace || sandbox.WorkerUID <= 0 || os.Geteuid() != sandbox.WorkerUID || os.Getegid() != sandbox.WorkerGID {
		return nil, nil, scanError("ARCHIVE_SANDBOX_UNVERIFIED", "The archive extraction sandbox is not a verified unprivileged private tmpfs.", "Run extraction as the scanner worker in its private mount namespace and bounded tmpfs.", nil)
	}
	if !extractionParentIsTmpfs(sandbox.ParentPath) {
		return nil, nil, scanError("ARCHIVE_SANDBOX_UNVERIFIED", "The archive extraction parent is not tmpfs-backed.", "Use the scanner worker's bounded private tmpfs extraction root.", nil)
	}
	parent, err := os.OpenRoot(sandbox.ParentPath)
	if err != nil {
		return nil, nil, scanError("ARCHIVE_SANDBOX_UNVERIFIED", "The archive extraction parent could not be opened safely.", "Recreate the scanner worker sandbox and retry.", err)
	}
	directory, err := os.MkdirTemp(sandbox.ParentPath, "private-vm-extract-")
	if err != nil {
		parent.Close()
		return nil, nil, extractionError(err)
	}
	name := filepath.Base(directory)
	info, err := parent.Lstat(name)
	if err != nil || !info.IsDir() {
		_ = parent.RemoveAll(name)
		parent.Close()
		return nil, nil, extractionError(err)
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		_ = parent.RemoveAll(name)
		parent.Close()
		return nil, nil, extractionError(err)
	}
	return &Extraction{parent: parent, name: name, path: directory, identity: captureFileInfoIdentity(info)}, root, nil
}

func copyExact(ctx context.Context, destination io.Writer, source io.Reader, expected uint64) (uint64, error) {
	if expected > uint64(^uint64(0)>>1) {
		return 0, errors.New("size is not representable")
	}
	written, err := io.CopyBuffer(destination, &contextReader{ctx: ctx, reader: io.LimitReader(source, int64(expected)+1)}, make([]byte, 1<<20))
	if err != nil {
		return uint64(max(written, 0)), err
	}
	if written < 0 || uint64(written) != expected {
		return uint64(max(written, 0)), errors.New("expanded size mismatch")
	}
	return uint64(written), nil
}

func extractionError(err error) error {
	return scanError("ARCHIVE_EXTRACTION_FAILED", "Archive extraction did not complete inside its bounded sandbox.", "Reject this archive and destroy the disposable scanner.", err)
}
