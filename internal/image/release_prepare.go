package image

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
)

const (
	releaseSchemaVersion       = 1
	maxReleaseCommandOutput    = 4 << 20
	maxImageTreeEntries        = 1024
	maxImageTreeDepth          = 8
	maxImageTreePathBytes      = 4096
	maxReleaseCompressedBytes  = 64 << 30
	maxReleaseUncompressedSize = 2 << 40
)

// PrepareOptions contains the complete immutable identity required to build a
// release candidate. Every field is validated by Go; the workflow is only a
// transport for these values and cannot relax the producer contract.
type PrepareOptions struct {
	WorkDir          string
	OutputDir        string
	ImageTarget      string
	ClosureTarget    string
	ReleaseTag       string
	Role             string
	Bundle           string
	Repository       string
	SourceRepository string
	SourceCommit     string
	SourceRef        string
	Workflow         string
	RepositoryID     string
	OwnerID          string
	RunID            string
	RunAttempt       string
}

// ReleaseReceipt is non-secret pre-attestation evidence. Paths are fixed base
// names rather than runner-specific absolute paths.
type ReleaseReceipt struct {
	SchemaVersion         int      `json:"schema_version"`
	Project               string   `json:"project"`
	ReleaseTag            string   `json:"release_tag"`
	Role                  string   `json:"role"`
	Bundle                *string  `json:"bundle"`
	Repository            string   `json:"repository"`
	SourceRepository      string   `json:"source_repository"`
	SourceCommit          string   `json:"source_commit"`
	SourceRef             string   `json:"source_ref"`
	Workflow              string   `json:"workflow"`
	ImageDigest           string   `json:"image_digest"`
	UncompressedSHA256    string   `json:"uncompressed_sha256"`
	SBOMDigest            string   `json:"sbom_digest"`
	ManifestDigest        string   `json:"manifest_digest"`
	CompressedSizeBytes   int64    `json:"compressed_size_bytes"`
	UncompressedSizeBytes int64    `json:"uncompressed_size_bytes"`
	VirtualSizeBytes      int64    `json:"virtual_size_bytes"`
	Files                 []string `json:"files"`
}

// PrepareResult is returned to the narrow release command. It contains no
// credentials and uses fixed files below OutputDir.
type PrepareResult struct {
	Receipt       ReleaseReceipt
	PredicatePath string
	ReceiptPath   string
}

type boundedCommandRunner interface {
	Run(context.Context, string, string, ...string) ([]byte, error)
}

type execBoundedRunner struct{}

func (execBoundedRunner) Run(ctx context.Context, directory, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Dir = directory
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"TZ=UTC",
		"NIX_CONFIG=max-jobs = 1\ncores = 2",
	}
	output := newBoundedBuffer(maxReleaseCommandOutput)
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, contextError(ctx, err)
		}
		return nil, err
	}
	return output.Bytes(), nil
}

type boundedBuffer struct {
	data  []byte
	limit int
	full  bool
}

func newBoundedBuffer(limit int) *boundedBuffer { return &boundedBuffer{limit: limit} }

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := buffer.limit - len(buffer.data)
	if remaining < len(value) {
		buffer.full = true
		if remaining > 0 {
			buffer.data = append(buffer.data, value[:remaining]...)
		}
		return original, errors.New("command output exceeded bound")
	}
	buffer.data = append(buffer.data, value...)
	return original, nil
}

func (buffer *boundedBuffer) Bytes() []byte { return append([]byte(nil), buffer.data...) }

// PrepareRelease builds the canonical Nix image and exact runtime closure,
// validates and compresses one QCOW2, and writes deterministic manifest, SPDX,
// predicate and receipt files. The output directory is removed on every error,
// cancellation and timeout.
func PrepareRelease(ctx context.Context, options PrepareOptions) (PrepareResult, error) {
	return prepareRelease(ctx, options, execBoundedRunner{})
}

func prepareRelease(ctx context.Context, options PrepareOptions, runner boundedCommandRunner) (result PrepareResult, returnedErr error) {
	if err := validatePrepareOptions(options); err != nil {
		return PrepareResult{}, err
	}
	if err := verifyReleaseSource(ctx, runner, options); err != nil {
		return PrepareResult{}, err
	}
	if err := os.Mkdir(options.OutputDir, 0o700); err != nil {
		return PrepareResult{}, releaseInvalid("The private release output directory could not be created exclusively.", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(options.OutputDir)
		}
	}()

	imageOutput, err := buildOneNixOutput(ctx, runner, options.WorkDir, options.ImageTarget)
	if err != nil {
		return PrepareResult{}, err
	}
	closureOutput, err := buildOneNixOutput(ctx, runner, options.WorkDir, options.ClosureTarget)
	if err != nil {
		return PrepareResult{}, err
	}
	closure, err := readNixClosure(ctx, runner, options.WorkDir, closureOutput)
	if err != nil {
		return PrepareResult{}, err
	}
	imagePath, err := selectReleaseQCOW2(imageOutput)
	if err != nil {
		return PrepareResult{}, err
	}
	imageFile, imageInfo, virtualSize, err := openValidatedQCOW2(imagePath)
	if err != nil {
		return PrepareResult{}, err
	}
	defer imageFile.Close()

	uncompressedDigest, err := hashReleaseFile(ctx, imageFile, maxReleaseUncompressedSize)
	if err != nil {
		return PrepareResult{}, err
	}
	if _, err := imageFile.Seek(0, io.SeekStart); err != nil {
		return PrepareResult{}, releaseInvalid("The validated QCOW2 could not be rewound for compression.", err)
	}
	compressedPath := filepath.Join(options.OutputDir, "image.qcow2.zst")
	compressedSize, compressedDigest, err := compressReleaseImage(ctx, imageFile, compressedPath)
	if err != nil {
		return PrepareResult{}, err
	}
	builtAt, err := sourceTimestamp(ctx, runner, options)
	if err != nil {
		return PrepareResult{}, err
	}
	flakeDigest, _, err := hashPath(ctx, filepath.Join(options.WorkDir, "flake.lock"), 16<<20)
	if err != nil {
		return PrepareResult{}, releaseInvalid("The pinned flake.lock identity could not be calculated.", err)
	}
	bundle := releaseBundle(options.Role, options.Bundle)
	manifest := Manifest{
		SchemaVersion: 1, Project: "private-vm", Role: options.Role, Bundle: bundle,
		Architecture: "x86_64", SourceRepository: options.SourceRepository,
		SourceCommit: options.SourceCommit, SourceRef: options.SourceRef, Workflow: options.Workflow,
		ImageDigest: compressedDigest, UncompressedSHA256: strings.TrimPrefix(uncompressedDigest, "sha256:"),
		CompressedSizeBytes: compressedSize, UncompressedSizeBytes: imageInfo.Size(), VirtualSizeBytes: virtualSize,
		NixOSVersion: frozenNixOSVersion, FlakeLockSHA256: strings.TrimPrefix(flakeDigest, "sha256:"),
		GuestAPIMajor: 1, GuestAPIMinor: 0, MinimumQEMUVersion: frozenQEMUMinimum,
		Capabilities: append([]string(nil), roleCapabilities[options.Role]...), BuiltAt: builtAt,
	}
	sbomBytes, err := encodeReleaseSPDX(manifest, closure)
	if err != nil {
		return PrepareResult{}, err
	}
	manifest.SBOMDigest = digestBytes(sbomBytes)
	manifestBytes, err := encodeCanonicalJSON(manifest)
	if err != nil {
		return PrepareResult{}, releaseInvalid("The image manifest could not be encoded.", err)
	}
	if err := writeExclusive(filepath.Join(options.OutputDir, "sbom.spdx.json"), sbomBytes, 0o600); err != nil {
		return PrepareResult{}, err
	}
	if err := writeExclusive(filepath.Join(options.OutputDir, "manifest.json"), manifestBytes, 0o600); err != nil {
		return PrepareResult{}, err
	}
	predicateBytes, err := encodeReleasePredicate(options)
	if err != nil {
		return PrepareResult{}, err
	}
	predicatePath := filepath.Join(options.OutputDir, "predicate.json")
	if err := writeExclusive(predicatePath, predicateBytes, 0o600); err != nil {
		return PrepareResult{}, err
	}
	receipt := ReleaseReceipt{
		SchemaVersion: 1, Project: "private-vm", ReleaseTag: options.ReleaseTag,
		Role: options.Role, Bundle: bundle, Repository: options.Repository,
		SourceRepository: options.SourceRepository, SourceCommit: options.SourceCommit,
		SourceRef: options.SourceRef, Workflow: options.Workflow, ImageDigest: compressedDigest,
		UncompressedSHA256: strings.TrimPrefix(uncompressedDigest, "sha256:"),
		SBOMDigest:         manifest.SBOMDigest, ManifestDigest: digestBytes(manifestBytes),
		CompressedSizeBytes: compressedSize, UncompressedSizeBytes: imageInfo.Size(), VirtualSizeBytes: virtualSize,
		Files: []string{"image.qcow2.zst", "manifest.json", "sbom.spdx.json", "predicate.json"},
	}
	receiptBytes, err := encodeCanonicalJSON(receipt)
	if err != nil {
		return PrepareResult{}, releaseInvalid("The release receipt could not be encoded.", err)
	}
	receiptPath := filepath.Join(options.OutputDir, "release-receipt.json")
	if err := writeExclusive(receiptPath, receiptBytes, 0o600); err != nil {
		return PrepareResult{}, err
	}
	if err := syncReleaseDirectory(options.OutputDir); err != nil {
		return PrepareResult{}, err
	}
	keep = true
	return PrepareResult{Receipt: receipt, PredicatePath: predicatePath, ReceiptPath: receiptPath}, nil
}

func validatePrepareOptions(options PrepareOptions) error {
	cleanAbsolute := func(value string) bool {
		return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/"
	}
	if !cleanAbsolute(options.WorkDir) || !cleanAbsolute(options.OutputDir) || options.OutputDir == options.WorkDir {
		return releaseInvalid("Release paths must be absolute and distinct.", nil)
	}
	resolvedWork, workErr := filepath.EvalSymlinks(options.WorkDir)
	workInfo, workStatErr := os.Lstat(options.WorkDir)
	if workErr != nil || workStatErr != nil || resolvedWork != options.WorkDir || !workInfo.IsDir() || workInfo.Mode()&0o022 != 0 || fileUID(workInfo) != os.Geteuid() {
		return releaseInvalid("The checked-out release source must be a real owner-controlled directory.", errors.Join(workErr, workStatErr))
	}
	parent := filepath.Dir(options.OutputDir)
	resolved, err := filepath.EvalSymlinks(parent)
	info, statErr := os.Lstat(parent)
	if err != nil || statErr != nil || resolved != parent || !info.IsDir() || info.Mode()&0o022 != 0 || fileUID(info) != os.Geteuid() {
		return releaseInvalid("The release output parent must be a real owner-controlled directory not writable by group or other.", errors.Join(err, statErr))
	}
	if options.SourceRepository != officialRepository || options.Workflow != officialWorkflow ||
		options.RepositoryID != officialRepositoryID || options.OwnerID != officialRepositoryOwnerID ||
		!commitPattern.MatchString(options.SourceCommit) || options.SourceRef != "refs/tags/"+options.ReleaseTag ||
		!officialReleaseRefPattern.MatchString(options.SourceRef) || !decimalIdentifierPattern.MatchString(options.RunID) ||
		!decimalIdentifierPattern.MatchString(options.RunAttempt) || !validRoleBundle(options.Role, options.Bundle) {
		return releaseInvalid("The release identity does not match the frozen official tag, repository, workflow, run, role, or bundle contract.", nil)
	}
	expectedRepo := "ghcr.io/stevenbuglione/private-vm/" + releaseImageName(options.Role, options.Bundle)
	if options.Repository != expectedRepo || options.ImageTarget != "image-"+releaseImageName(options.Role, options.Bundle) ||
		options.ClosureTarget != "closure-"+releaseImageName(options.Role, options.Bundle) {
		return releaseInvalid("The role does not map to the exact frozen Nix and GHCR release targets.", nil)
	}
	return nil
}

func releaseImageName(role, bundle string) string {
	if role == "workstation" {
		return role + "-" + bundle
	}
	return role
}

func releaseBundle(role, bundle string) *string {
	if role != "workstation" {
		return nil
	}
	value := bundle
	return &value
}

func verifyReleaseSource(ctx context.Context, runner boundedCommandRunner, options PrepareOptions) error {
	checks := []struct {
		arguments []string
		expected  string
	}{
		{[]string{"rev-parse", "HEAD"}, options.SourceCommit},
		{[]string{"rev-list", "-n", "1", options.ReleaseTag}, options.SourceCommit},
		{[]string{"remote", "get-url", "origin"}, "https://github.com/" + officialRepository},
		{[]string{"status", "--porcelain=v1", "--untracked-files=all"}, ""},
	}
	for _, check := range checks {
		output, err := runner.Run(ctx, options.WorkDir, "git", check.arguments...)
		if ctx.Err() != nil {
			return contextError(ctx, err)
		}
		if err != nil || strings.TrimSpace(string(output)) != check.expected {
			return releaseInvalid("The release source is dirty or the protected tag does not identify the checked-out commit.", err)
		}
	}
	if _, err := runner.Run(ctx, options.WorkDir, "git", "merge-base", "--is-ancestor", options.SourceCommit, "refs/remotes/origin/main"); err != nil {
		if ctx.Err() != nil {
			return contextError(ctx, err)
		}
		return releaseInvalid("The protected release tag commit is not reachable from the fetched official main branch.", err)
	}
	return nil
}

func buildOneNixOutput(ctx context.Context, runner boundedCommandRunner, directory, target string) (string, error) {
	output, err := runner.Run(ctx, directory, "nix", "build", "--no-link", "--print-out-paths", ".#"+target)
	if err != nil {
		if ctx.Err() != nil {
			return "", contextError(ctx, err)
		}
		return "", releaseBuildFailed(err)
	}
	lines := nonemptyLines(output)
	if len(lines) != 1 || !canonicalStorePath(lines[0]) {
		return "", releaseBuildFailed(errors.New("nix returned an invalid output set"))
	}
	return lines[0], nil
}

func readNixClosure(ctx context.Context, runner boundedCommandRunner, directory, outputPath string) ([]string, error) {
	data, err := runner.Run(ctx, directory, "nix", "path-info", "-r", outputPath)
	if err != nil {
		if ctx.Err() != nil {
			return nil, contextError(ctx, err)
		}
		return nil, releaseBuildFailed(err)
	}
	lines := nonemptyLines(data)
	if len(lines) == 0 || len(lines) > 50_000 {
		return nil, releaseInvalid("The exact runtime Nix closure is empty or exceeds its package bound.", nil)
	}
	sort.Strings(lines)
	lines = compactStrings(lines)
	for _, value := range lines {
		if !canonicalStorePath(value) {
			return nil, releaseInvalid("The runtime closure contains a noncanonical Nix store path.", nil)
		}
	}
	return lines, nil
}

func nonemptyLines(data []byte) []string {
	var result []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 8192)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func canonicalStorePath(value string) bool {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value || !strings.HasPrefix(value, "/nix/store/") {
		return false
	}
	_, _, ok := parseNixStoreURI("file://" + value)
	return ok
}

func selectReleaseQCOW2(root string) (string, error) {
	if !canonicalStorePath(root) {
		return "", releaseInvalid("The Nix image output path is not canonical.", nil)
	}
	return selectQCOW2Tree(root)
}

func selectQCOW2Tree(root string) (string, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", releaseInvalid("The Nix image output is not a real directory.", err)
	}
	count := 0
	var candidates []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		relative, err := filepath.Rel(root, path)
		if err != nil || len(relative) > maxImageTreePathBytes || strings.Count(relative, string(filepath.Separator)) > maxImageTreeDepth || count > maxImageTreeEntries {
			return errors.New("image output tree exceeds bound")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("image output contains unsupported entry")
		}
		if info.Mode().IsRegular() && strings.EqualFold(filepath.Ext(entry.Name()), ".qcow2") {
			candidates = append(candidates, path)
		}
		return nil
	})
	if err != nil || len(candidates) != 1 {
		return "", releaseInvalid("The Nix image output must contain exactly one bounded regular QCOW2 and no links or special files.", err)
	}
	return candidates[0], nil
}

func openValidatedQCOW2(path string) (*os.File, os.FileInfo, int64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, 0, releaseInvalid("The selected QCOW2 could not be opened without following links.", err)
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 104 || info.Size() > maxReleaseUncompressedSize {
		return nil, nil, 0, releaseInvalid("The selected QCOW2 has an unsafe type or physical size.", err)
	}
	header := make([]byte, 104)
	if _, err := io.ReadFull(file, header); err != nil {
		return nil, nil, 0, releaseInvalid("The QCOW2 header could not be read completely.", err)
	}
	validatedVirtualSize, err := validateQCOW2Header(header, info.Size())
	if err != nil {
		return nil, nil, 0, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, nil, 0, releaseInvalid("The validated QCOW2 could not be rewound.", err)
	}
	failed = false
	return file, info, validatedVirtualSize, nil
}

func validateQCOW2Header(header []byte, physicalSize int64) (int64, error) {
	if len(header) != 104 {
		return 0, releaseInvalid("The selected QCOW2 header has an unsupported length.", nil)
	}
	version := binary.BigEndian.Uint32(header[4:8])
	clusterBits := binary.BigEndian.Uint32(header[20:24])
	virtualSize := binary.BigEndian.Uint64(header[24:32])
	cryptMethod := binary.BigEndian.Uint32(header[32:36])
	if string(header[:4]) != "QFI\xfb" || version != 3 || binary.BigEndian.Uint64(header[8:16]) != 0 ||
		binary.BigEndian.Uint32(header[16:20]) != 0 || clusterBits < 9 || clusterBits > 21 ||
		virtualSize == 0 || virtualSize > maxReleaseUncompressedSize || virtualSize < uint64(physicalSize) || virtualSize%512 != 0 || cryptMethod != 0 ||
		binary.BigEndian.Uint64(header[72:80]) != 0 || binary.BigEndian.Uint64(header[80:88]) != 0 ||
		binary.BigEndian.Uint64(header[88:96]) != 0 || binary.BigEndian.Uint32(header[96:100]) != 4 ||
		binary.BigEndian.Uint32(header[100:104]) != 104 {
		return 0, releaseInvalid("The selected image is not an unencrypted, backing-file-free QCOW2 v3 within frozen bounds.", nil)
	}
	return int64(virtualSize), nil
}

func hashReleaseFile(ctx context.Context, file *os.File, maximum int64) (string, error) {
	hash := sha256.New()
	written, err := copyWithContext(ctx, hash, io.LimitReader(file, maximum+1))
	if err != nil {
		return "", contextError(ctx, releaseInvalid("The QCOW2 could not be hashed completely.", err))
	}
	if written > maximum {
		return "", releaseInvalid("The QCOW2 exceeds the release byte bound.", nil)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func compressReleaseImage(ctx context.Context, source io.Reader, destination string) (int64, string, error) {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, "", releaseInvalid("The compressed image staging file could not be created exclusively.", err)
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(destination)
		}
	}()
	hash := sha256.New()
	counter := &countingWriter{writer: io.MultiWriter(file, hash), maximum: maxReleaseCompressedBytes}
	encoder, err := zstd.NewWriter(counter,
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderLevel(zstd.SpeedBetterCompression),
		zstd.WithWindowSize(8<<20),
		zstd.WithEncoderCRC(true),
	)
	if err != nil {
		return 0, "", releaseInvalid("The deterministic zstd encoder could not be initialized.", err)
	}
	_, copyErr := copyWithContext(ctx, encoder, source)
	closeErr := encoder.Close()
	if copyErr != nil {
		return 0, "", contextError(ctx, releaseInvalid("The QCOW2 compression did not complete.", copyErr))
	}
	if closeErr != nil {
		return 0, "", releaseInvalid("The zstd stream could not be finalized.", closeErr)
	}
	if err := file.Sync(); err != nil {
		return 0, "", releaseInvalid("The compressed image could not be synchronized.", err)
	}
	if err := file.Close(); err != nil {
		return 0, "", releaseInvalid("The compressed image could not be closed.", err)
	}
	success = true
	return counter.written, "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

type countingWriter struct {
	writer  io.Writer
	written int64
	maximum int64
}

func (writer *countingWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > writer.maximum-writer.written {
		return 0, errors.New("output exceeds bound")
	}
	n, err := writer.writer.Write(value)
	writer.written += int64(n)
	return n, err
}

func encodeReleaseSPDX(manifest Manifest, closure []string) ([]byte, error) {
	truth, falsity := true, false
	imageChecksum := []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: manifest.UncompressedSHA256}}
	emptyChecksums := []spdxChecksum{}
	document := spdxDocument{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		Name:              manifestArtifactName(manifest),
		DocumentNamespace: "https://private-vm.dev/spdx/images/" + manifestArtifactName(manifest) + "/" + strings.TrimPrefix(manifest.ImageDigest, "sha256:"),
		CreationInfo:      spdxCreationInfo{Created: manifest.BuiltAt, Creators: []string{"Tool: private-vm release workflow"}},
		DocumentDescribes: []string{imageSPDXID},
		Packages:          []spdxPackage{{SPDXID: imageSPDXID, Name: manifestArtifactName(manifest), VersionInfo: manifest.NixOSVersion, DownloadLocation: "NOASSERTION", FilesAnalyzed: &truth, Checksums: &imageChecksum}},
		Files:             []spdxFile{{SPDXID: imageFileSPDXID, FileName: "./image.qcow2", FileTypes: []string{"BINARY"}, Checksums: imageChecksum}},
		Relationships: []spdxRelationship{
			{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: imageSPDXID},
			{SPDXElementID: imageSPDXID, RelationshipType: "CONTAINS", RelatedSPDXElement: imageFileSPDXID},
		},
	}
	for _, storePath := range closure {
		hash, name, ok := parseNixStoreURI("file://" + storePath)
		if !ok {
			return nil, releaseInvalid("The runtime closure cannot be represented as a canonical SPDX package.", nil)
		}
		identifier := "SPDXRef-Package-" + hash
		document.Packages = append(document.Packages, spdxPackage{
			SPDXID: identifier, Name: name, VersionInfo: "NOASSERTION", DownloadLocation: "file://" + storePath,
			FilesAnalyzed: &falsity, Checksums: &emptyChecksums,
		})
		document.Relationships = append(document.Relationships, spdxRelationship{SPDXElementID: imageSPDXID, RelationshipType: "DEPENDS_ON", RelatedSPDXElement: identifier})
	}
	return encodeCanonicalJSON(document)
}

func encodeReleasePredicate(options PrepareOptions) ([]byte, error) {
	repositoryURL := "https://github.com/" + officialRepository
	predicate := githubPredicate{
		BuildDefinition: &githubBuildDefinition{
			BuildType:            githubWorkflowBuildType,
			ExternalParameters:   &githubExternalParameters{Workflow: &githubWorkflowParameters{Ref: options.SourceRef, Repository: repositoryURL, Path: "/" + officialWorkflow}},
			InternalParameters:   &githubInternalParameters{GitHub: &githubInternalIdentity{EventName: "push", RepositoryID: options.RepositoryID, RepositoryOwnerID: options.OwnerID}},
			ResolvedDependencies: []githubResolvedDependency{{URI: "git+" + repositoryURL + "@" + options.SourceRef, Digest: &gitDependencyDigest{GitCommit: options.SourceCommit}}},
		},
		RunDetails: &githubRunDetails{
			Builder:  &githubBuilder{ID: githubHostedRunnerBuilder},
			Metadata: &githubMetadata{InvocationID: repositoryURL + "/actions/runs/" + options.RunID + "/attempts/" + options.RunAttempt},
		},
	}
	return encodeCanonicalJSON(predicate)
}

func sourceTimestamp(ctx context.Context, runner boundedCommandRunner, options PrepareOptions) (string, error) {
	data, err := runner.Run(ctx, options.WorkDir, "git", "show", "-s", "--format=%ct", options.SourceCommit)
	if err != nil {
		if ctx.Err() != nil {
			return "", contextError(ctx, err)
		}
		return "", releaseBuildFailed(err)
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || seconds < 1 {
		return "", releaseInvalid("The source commit timestamp is invalid.", err)
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339), nil
}

func hashPath(ctx context.Context, path string, maximum int64) (string, int64, error) {
	file, _, err := openBoundedRegular(path, maximum)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := copyWithContext(ctx, hash, io.LimitReader(file, maximum+1))
	if err != nil || written > maximum {
		return "", written, errors.New("file exceeds bound or could not be read")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), written, nil
}

func openBoundedRegular(path string, maximum int64) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum || fileUID(info) != os.Geteuid() {
		_ = file.Close()
		return nil, nil, errors.Join(err, errors.New("unsafe regular file"))
	}
	return file, info, nil
}

func digestBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func encodeCanonicalJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func writeExclusive(path string, data []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return releaseInvalid("A release evidence file could not be created exclusively.", err)
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return releaseInvalid("A release evidence file could not be written completely.", err)
	}
	if err := file.Sync(); err != nil {
		return releaseInvalid("A release evidence file could not be synchronized.", err)
	}
	if err := file.Close(); err != nil {
		return releaseInvalid("A release evidence file could not be closed.", err)
	}
	success = true
	return nil
}

func syncReleaseDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return releaseInvalid("The release output directory could not be opened for synchronization.", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return releaseInvalid("The release output directory could not be synchronized.", err)
	}
	return nil
}

func releaseInvalid(message string, cause error) error {
	return imageError(CodeReleaseInvalid, message, "Use the protected official release workflow with canonical source, role, target and bounded artifact inputs.", cause)
}

func releaseBuildFailed(cause error) error {
	return imageError(CodeReleaseBuildFailed, "The canonical Nix release build or closure enumeration failed.", "Fix the pinned source build locally, then create a new protected Git release tag.", cause)
}

var _ boundedCommandRunner = execBoundedRunner{}
