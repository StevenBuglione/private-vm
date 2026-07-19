package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maxCacheRecordBytes = 64 << 10

// Cache owns one already-created, trusted, non-writable-by-others root. ownerUID
// is explicit so production callers must request root ownership while tests can
// use an isolated effective-user directory.
type Cache struct {
	root     string
	ownerUID int
}

func NewCache(root string, ownerUID int) (*Cache, error) {
	if ownerUID < 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return nil, imageError(CodeCacheInvalid, "The image cache root is invalid.", "Use the configured absolute private-vm image-cache directory.", nil)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return nil, imageError(CodeCacheInvalid, "The image cache root is missing or contains a symbolic link.", "Create the trusted cache directory through the private-vm package integration.", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&0o022 != 0 || fileUID(info) != ownerUID {
		return nil, imageError(CodeCacheInvalid, "The image cache root has unsafe ownership, type or permissions.", "Require the cache root to be an owner-controlled real directory not writable by group or other.", err)
	}
	digestRoot := filepath.Join(root, "sha256")
	if err := os.Mkdir(digestRoot, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, imageError(CodeCacheInvalid, "The digest cache directory could not be created.", "Verify cache ownership and permissions, then retry.", err)
	}
	if err := validateOwnedDirectory(digestRoot, ownerUID, false); err != nil {
		return nil, err
	}
	return &Cache{root: root, ownerUID: ownerUID}, nil
}

type stagedEntry struct {
	directory string
	final     string
	entry     Entry
}

func (cache *Cache) stage(manifestDigest string) (stagedEntry, error) {
	parsed, err := parseDigest(manifestDigest)
	if err != nil {
		return stagedEntry{}, imageError(CodeCacheInvalid, "The cache key is not a canonical SHA-256 digest.", "Resolve the OCI manifest before creating a cache entry.", err)
	}
	digestRoot := filepath.Join(cache.root, "sha256")
	directory, err := os.MkdirTemp(digestRoot, ".partial-"+parsed.Encoded()+"-")
	if err != nil {
		return stagedEntry{}, imageError(CodeCacheInvalid, "A hidden cache staging directory could not be created.", "Verify cache ownership and free space, then retry.", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return stagedEntry{}, imageError(CodeCacheInvalid, "The hidden cache staging directory could not be secured.", "Verify cache filesystem permission support, then retry.", err)
	}
	entry := entryFor(directory, manifestDigest)
	return stagedEntry{directory: directory, final: digestPath(cache.root, manifestDigest), entry: entry}, nil
}

func (cache *Cache) load(ctx context.Context, manifestDigest string, limits Limits) (Entry, bool, error) {
	if _, err := parseDigest(manifestDigest); err != nil {
		return Entry{}, false, imageError(CodeCacheInvalid, "The cache key is not a canonical SHA-256 digest.", "Resolve the OCI manifest before reading the cache.", err)
	}
	entry := entryFor(digestPath(cache.root, manifestDigest), manifestDigest)
	_, err := os.Lstat(entry.Directory)
	if errors.Is(err, fs.ErrNotExist) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, imageError(CodeCacheInvalid, "The digest cache entry could not be inspected.", "Verify cache ownership and filesystem health, then retry.", err)
	}
	if err := validateEntry(ctx, entry, cache.ownerUID, limits); err != nil {
		return Entry{}, false, err
	}
	return entry, true, nil
}

func (cache *Cache) publish(ctx context.Context, stage stagedEntry, limits Limits) (Entry, bool, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, false, err
	}
	if err := syncDirectory(stage.directory); err != nil {
		return Entry{}, false, imageError(CodeCacheInvalid, "The staged cache directory could not be synchronized.", "Verify cache storage health and retry.", err)
	}
	// Synchronize the parent before publication so every fallible durability
	// check happens while the entry is still hidden. The cache is rebuildable;
	// a later host crash may lose the rename but cannot expose partial content.
	if err := syncDirectory(filepath.Dir(stage.final)); err != nil {
		return Entry{}, false, imageError(CodeCacheInvalid, "The digest cache directory could not be synchronized.", "Verify cache storage health before publishing an entry.", err)
	}
	if err := os.Rename(stage.directory, stage.final); err != nil {
		if existing, ok, loadErr := cache.load(ctx, stage.entry.ManifestDigest, limits); loadErr == nil && ok {
			_ = removeStage(stage.directory)
			return existing, true, nil
		}
		return Entry{}, false, imageError(CodeCacheConflict, "The immutable digest cache entry could not be published atomically.", "Verify cache ownership and remove only a separately confirmed invalid entry before retrying.", err)
	}
	entry := entryFor(stage.final, stage.entry.ManifestDigest)
	return entry, false, nil
}

func entryFor(directory, manifestDigest string) Entry {
	return Entry{
		ManifestDigest: manifestDigest,
		Directory:      directory,
		ImagePath:      filepath.Join(directory, "image.qcow2"),
		ManifestPath:   filepath.Join(directory, "manifest.json"),
		SBOMPath:       filepath.Join(directory, "sbom.spdx.json"),
		ProvenancePath: filepath.Join(directory, "provenance.json"),
		RecordPath:     filepath.Join(directory, cacheRecordName),
	}
}

type cacheRecord struct {
	SchemaVersion     int               `json:"schema_version"`
	OCIManifestDigest string            `json:"oci_manifest_digest"`
	Files             []cacheFileRecord `json:"files"`
}

type cacheFileRecord struct {
	Name               string `json:"name"`
	MediaType          string `json:"media_type"`
	SourceDigest       string `json:"source_digest"`
	InstalledDigest    string `json:"installed_digest"`
	SourceSizeBytes    int64  `json:"source_size_bytes"`
	InstalledSizeBytes int64  `json:"installed_size_bytes"`
}

func writeCacheRecord(path string, record cacheRecord) error {
	buffer := new(strings.Builder)
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(record); err != nil || buffer.Len() > maxCacheRecordBytes {
		return imageError(CodeCacheInvalid, "The cache record could not be encoded within its bound.", "Install matching private-vm image components and retry.", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return imageError(CodeCacheInvalid, "The cache record could not be created safely.", "Verify cache ownership and retry.", err)
	}
	success := false
	defer func() {
		if !success {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := io.WriteString(file, buffer.String()); err != nil {
		return imageError(CodeCacheInvalid, "The cache record could not be written completely.", "Verify cache storage health and retry.", err)
	}
	if err := file.Sync(); err != nil {
		return imageError(CodeCacheInvalid, "The cache record could not be synchronized.", "Verify cache storage health and retry.", err)
	}
	if err := file.Close(); err != nil {
		return imageError(CodeCacheInvalid, "The cache record could not be closed safely.", "Verify cache storage health and retry.", err)
	}
	success = true
	return nil
}

func readCacheRecord(path string) (cacheRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return cacheRecord{}, imageError(CodeCacheInvalid, "The cache record could not be opened.", "Pull the image again after separately confirming and removing the invalid entry.", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCacheRecordBytes+1))
	if err != nil || len(data) > maxCacheRecordBytes {
		return cacheRecord{}, imageError(CodeCacheInvalid, "The cache record exceeds its bound or could not be read.", "Pull the image again after separately confirming and removing the invalid entry.", err)
	}
	var record cacheRecord
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return cacheRecord{}, imageError(CodeCacheInvalid, "The cache record is malformed or contains unknown fields.", "Pull the image again after separately confirming and removing the invalid entry.", err)
	}
	return record, nil
}

func makeStageReadOnly(directory string, ownerUID int) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return imageError(CodeCacheInvalid, "The staged cache directory could not be inspected.", "Verify cache filesystem health and retry.", err)
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || fileUID(info) != ownerUID {
			return imageError(CodeCacheInvalid, "A staged cache component has unsafe type or ownership.", "Use only regular owner-controlled cache files.", err)
		}
		if err := os.Chmod(path, 0o444); err != nil {
			return imageError(CodeCacheInvalid, "A staged cache component could not be made read-only.", "Verify cache filesystem permission support and retry.", err)
		}
	}
	if err := os.Chmod(directory, 0o555); err != nil {
		return imageError(CodeCacheInvalid, "The staged cache directory could not be made immutable.", "Verify cache filesystem permission support and retry.", err)
	}
	return nil
}

func validateEntry(ctx context.Context, entry Entry, ownerUID int, limits Limits) error {
	if err := validateOwnedDirectory(entry.Directory, ownerUID, true); err != nil {
		return err
	}
	children, err := os.ReadDir(entry.Directory)
	if err != nil {
		return imageError(CodeCacheInvalid, "The cache entry could not be enumerated.", "Pull the image again after separately confirming and removing the invalid entry.", err)
	}
	expectedNames := map[string]struct{}{
		"image.qcow2": {}, "manifest.json": {}, "sbom.spdx.json": {},
		"provenance.json": {}, cacheRecordName: {},
	}
	if len(children) != len(expectedNames) {
		return imageError(CodeCacheInvalid, "The cache entry contains a missing or unexpected component.", "Pull the image again after separately confirming and removing the invalid entry.", nil)
	}
	for _, child := range children {
		if _, ok := expectedNames[child.Name()]; !ok {
			return imageError(CodeCacheInvalid, "The cache entry contains an unexpected component.", "Pull the image again after separately confirming and removing the invalid entry.", nil)
		}
		info, err := os.Lstat(filepath.Join(entry.Directory, child.Name()))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 || fileUID(info) != ownerUID {
			return imageError(CodeCacheInvalid, "A cache component has unsafe type, mode or ownership.", "Pull the image again after separately confirming and removing the invalid entry.", err)
		}
	}

	record, err := readCacheRecord(entry.RecordPath)
	if err != nil {
		return err
	}
	if record.SchemaVersion != 1 || record.OCIManifestDigest != entry.ManifestDigest || len(record.Files) != len(componentPolicy) {
		return imageError(CodeCacheInvalid, "The cache record identity or component count is invalid.", "Pull the image again after separately confirming and removing the invalid entry.", nil)
	}
	if _, err := parseDigest(record.OCIManifestDigest); err != nil {
		return imageError(CodeCacheInvalid, "The cache record digest is invalid.", "Pull the image again after separately confirming and removing the invalid entry.", err)
	}

	seen := make(map[string]struct{}, len(record.Files))
	for _, fileRecord := range record.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		specification, ok := componentPolicy[fileRecord.MediaType]
		if !ok || specification.installedName != fileRecord.Name {
			return imageError(CodeCacheInvalid, "A cache record component type or filename is invalid.", "Pull the image again after separately confirming and removing the invalid entry.", nil)
		}
		if _, duplicate := seen[fileRecord.Name]; duplicate {
			return imageError(CodeCacheInvalid, "The cache record contains a duplicate component.", "Pull the image again after separately confirming and removing the invalid entry.", nil)
		}
		seen[fileRecord.Name] = struct{}{}
		if _, err := parseDigest(fileRecord.SourceDigest); err != nil {
			return imageError(CodeCacheInvalid, "A cache source digest is invalid.", "Pull the image again after separately confirming and removing the invalid entry.", err)
		}
		if _, err := parseDigest(fileRecord.InstalledDigest); err != nil {
			return imageError(CodeCacheInvalid, "A cache installed digest is invalid.", "Pull the image again after separately confirming and removing the invalid entry.", err)
		}
		maximumSource, maximumInstalled := limits.MaxMetadataBytes, limits.MaxMetadataBytes
		if specification.image {
			maximumSource, maximumInstalled = limits.MaxCompressedImageBytes, limits.MaxUncompressedImageBytes
		}
		if fileRecord.SourceSizeBytes < 1 || fileRecord.SourceSizeBytes > maximumSource ||
			fileRecord.InstalledSizeBytes < 1 || fileRecord.InstalledSizeBytes > maximumInstalled {
			return imageError(CodeCacheInvalid, "A cache component size is outside its bound.", "Pull the image again after separately confirming and removing the invalid entry.", nil)
		}
		if err := verifyInstalledFile(ctx, filepath.Join(entry.Directory, fileRecord.Name), fileRecord.InstalledSizeBytes, fileRecord.InstalledDigest); err != nil {
			return err
		}
	}
	return nil
}

func verifyInstalledFile(ctx context.Context, path string, expectedSize int64, expectedDigest string) error {
	file, err := os.Open(path)
	if err != nil {
		return imageError(CodeCacheInvalid, "A cache component could not be opened for integrity verification.", "Pull the image again after separately confirming and removing the invalid entry.", err)
	}
	defer file.Close()
	hasher := sha256.New()
	size, err := copyWithContext(ctx, hasher, io.LimitReader(file, expectedSize+1))
	if err != nil {
		return contextError(ctx, imageError(CodeCacheInvalid, "A cache component could not be read for integrity verification.", "Pull the image again after separately confirming and removing the invalid entry.", err))
	}
	actual := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if size != expectedSize || actual != expectedDigest {
		return imageError(CodeDigestMismatch, "An installed cache component failed its recorded integrity check.", "Do not launch the image; pull it again by immutable digest.", nil)
	}
	return nil
}

func validateOwnedDirectory(path string, ownerUID int, readOnly bool) error {
	info, err := os.Lstat(path)
	expectedMode := fs.FileMode(0o755)
	if readOnly {
		expectedMode = 0o555
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != expectedMode || fileUID(info) != ownerUID {
		return imageError(CodeCacheInvalid, "A cache directory has unsafe ownership, type or permissions.", "Restore the package-managed cache ownership and modes before retrying.", err)
	}
	return nil
}

func fileUID(info fs.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func removeStage(path string) error {
	if path == "" || !strings.HasPrefix(filepath.Base(path), ".partial-") {
		return errors.New("refusing to remove non-staging path")
	}
	_ = os.Chmod(path, 0o700)
	return os.RemoveAll(path)
}
