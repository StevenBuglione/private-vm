package image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
)

const (
	MediaTypeQCOW2Zstd   = "application/vnd.private-vm.qcow2+zstd"
	MediaTypeManifest    = "application/vnd.private-vm.manifest.v1+json"
	MediaTypeSBOM        = "application/spdx+json"
	MediaTypeProvenance  = "application/vnd.dev.sigstore.bundle+json"
	emptyConfigMediaType = "application/vnd.oci.empty.v1+json"
	canonicalEmptyConfig = "{}"

	cacheRecordName    = "cache-entry.json"
	ociTitleAnnotation = "org.opencontainers.image.title"
)

var componentPolicy = map[string]componentSpec{
	MediaTypeQCOW2Zstd:  {sourceName: "image.qcow2.zst", installedName: "image.qcow2", image: true},
	MediaTypeManifest:   {sourceName: "manifest.json", installedName: "manifest.json"},
	MediaTypeSBOM:       {sourceName: "sbom.spdx.json", installedName: "sbom.spdx.json"},
	MediaTypeProvenance: {sourceName: "provenance.json", installedName: "provenance.json"},
}

type componentSpec struct {
	sourceName    string
	installedName string
	image         bool
}

// canonicalManifestWire deliberately contains only the fields allowed by the
// frozen v1 artifact layout. Decoding directly into the broader OCI structs
// would accept known optional redirect, embedded-data and metadata channels.
type canonicalManifestWire struct {
	SchemaVersion int                     `json:"schemaVersion"`
	MediaType     string                  `json:"mediaType"`
	Config        canonicalDescriptorWire `json:"config"`
	Layers        []canonicalLayerWire    `json:"layers"`
}

type canonicalDescriptorWire struct {
	MediaType string        `json:"mediaType"`
	Digest    digest.Digest `json:"digest"`
	Size      int64         `json:"size"`
}

type canonicalLayerWire struct {
	MediaType   string            `json:"mediaType"`
	Digest      digest.Digest     `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
}

type artifactManifest struct {
	Config ocispec.Descriptor
	Layers []ocispec.Descriptor
}

// Limits are copied by NewPuller and cannot be changed during a pull.
type Limits struct {
	MaxManifestBytes          int64
	MaxMetadataBytes          int64
	MaxCompressedImageBytes   int64
	MaxUncompressedImageBytes int64
	MaxComponents             int
	Timeout                   time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxManifestBytes:          1 << 20,
		MaxMetadataBytes:          16 << 20,
		MaxCompressedImageBytes:   16 << 30,
		MaxUncompressedImageBytes: 128 << 30,
		MaxComponents:             4,
		Timeout:                   30 * time.Minute,
	}
}

func (limits Limits) validate() error {
	if limits.MaxManifestBytes < 1 || limits.MaxManifestBytes > 4<<20 ||
		limits.MaxMetadataBytes < 1 || limits.MaxMetadataBytes > 64<<20 ||
		limits.MaxCompressedImageBytes < 1 || limits.MaxCompressedImageBytes > 64<<30 ||
		limits.MaxUncompressedImageBytes < 1 || limits.MaxUncompressedImageBytes > 2<<40 ||
		limits.MaxComponents < len(componentPolicy) || limits.MaxComponents > 16 ||
		limits.Timeout < time.Second || limits.Timeout > 2*time.Hour {
		return imageError(
			CodeArtifactLimit,
			"The image pull limits are outside the supported bounds.",
			"Use finite limits no larger than the documented IMG-001 hard ceilings.",
			nil,
		)
	}
	return nil
}

// Entry is one verified, immutable cache directory addressed by the resolved
// OCI manifest digest. A tag is never retained as execution identity.
type Entry struct {
	ManifestDigest string
	Directory      string
	ImagePath      string
	ManifestPath   string
	SBOMPath       string
	ProvenancePath string
	RecordPath     string
}

// Verifier is the dependency seam implemented by IMG-002 and IMG-003. A pull
// cannot become an installed/runnable cache entry unless this callback accepts
// the complete staged artifact.
type Verifier interface {
	Verify(context.Context, Entry) error
}

type VerificationFunc func(context.Context, Entry) error

func (fn VerificationFunc) Verify(ctx context.Context, entry Entry) error {
	if fn == nil {
		return imageError(CodeVerificationMissing, "No image trust verifier is available.", "Install the manifest, SBOM and provenance verification components before pulling images.", nil)
	}
	return fn(ctx, entry)
}

// Puller resolves a reference, fetches and independently hashes its OCI graph,
// extracts fixed regular files into a hidden staging directory, invokes the
// required trust verifier, and only then atomically exposes the digest path.
type Puller struct {
	factory    RepositoryFactory
	cache      *Cache
	verifier   Verifier
	limits     Limits
	decompress func(context.Context, io.Reader, io.Writer, int64) (int64, string, error)
}

func NewPuller(factory RepositoryFactory, cache *Cache, verifier Verifier, limits Limits) (*Puller, error) {
	if nilLike(factory) || cache == nil {
		return nil, imageError(
			CodeCacheInvalid,
			"The image puller is missing a required repository or cache boundary.",
			"Install matching private-vm components and retry.",
			nil,
		)
	}
	if nilLike(verifier) {
		return nil, imageError(
			CodeVerificationMissing,
			"No image trust verifier is available.",
			"Install the manifest, SBOM and provenance verification components before pulling images.",
			nil,
		)
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	return &Puller{factory: factory, cache: cache, verifier: verifier, limits: limits, decompress: decompressZstd}, nil
}

func (puller *Puller) Pull(ctx context.Context, reference string) (Entry, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, contextError(ctx, err)
	}
	parsed, err := parsePullReference(reference)
	if err != nil {
		return Entry{}, imageError(
			CodeReferenceInvalid,
			"The OCI image reference is invalid or has no tag or digest.",
			"Use a complete registry/repository:tag or registry/repository@sha256:digest reference.",
			err,
		)
	}

	pullCtx, cancel := context.WithTimeout(ctx, puller.limits.Timeout)
	defer cancel()

	repo, err := puller.factory.Open(parsed.Registry + "/" + parsed.Repository)
	if err != nil {
		return Entry{}, contextError(pullCtx, imageError(
			CodeResolveFailed,
			"The OCI repository could not be opened.",
			"Verify the registry and repository configuration, then retry.",
			err,
		))
	}
	if nilLike(repo) {
		return Entry{}, imageError(
			CodeResolveFailed,
			"The OCI repository client is unavailable.",
			"Install matching private-vm image components and retry.",
			nil,
		)
	}

	// Resolve is deliberately the first remote operation. Layers are fetched
	// only by descriptors from this immutable manifest digest.
	manifestDescriptor, err := repo.Resolve(pullCtx, parsed.Reference)
	if err != nil {
		return Entry{}, contextError(pullCtx, imageError(
			CodeResolveFailed,
			"The OCI image reference could not be resolved to an immutable digest.",
			"Verify that the public image exists and retry when the registry is responsive.",
			err,
		))
	}
	if err := validateManifestDescriptor(manifestDescriptor, puller.limits); err != nil {
		return Entry{}, err
	}
	if digestReference(parsed.Reference) && parsed.Reference != manifestDescriptor.Digest.String() {
		return Entry{}, imageError(
			CodeDigestMismatch,
			"The registry resolved a different digest than the requested execution identity.",
			"Do not use the artifact; retry by the expected immutable digest.",
			nil,
		)
	}

	if existing, ok, err := puller.cache.load(pullCtx, manifestDescriptor.Digest.String(), puller.limits); err != nil {
		return Entry{}, contextError(pullCtx, err)
	} else if ok {
		if err := puller.verify(pullCtx, existing); err != nil {
			return Entry{}, err
		}
		return existing, nil
	}

	stage, err := puller.cache.stage(manifestDescriptor.Digest.String())
	if err != nil {
		return Entry{}, err
	}
	installed := false
	defer func() {
		if !installed {
			_ = removeStage(stage.directory)
		}
	}()

	manifestBytes, err := fetchBytes(pullCtx, repo, manifestDescriptor, puller.limits.MaxManifestBytes)
	if err != nil {
		return Entry{}, contextError(pullCtx, err)
	}
	document, err := decodeOCIManifest(manifestBytes, puller.limits)
	if err != nil {
		return Entry{}, err
	}

	if err := fetchCanonicalConfig(pullCtx, repo, document.Config); err != nil {
		return Entry{}, contextError(pullCtx, err)
	}

	record := cacheRecord{SchemaVersion: 1, OCIManifestDigest: manifestDescriptor.Digest.String()}
	for _, descriptor := range document.Layers {
		specification := componentPolicy[descriptor.MediaType]
		fileRecord, err := puller.installComponent(pullCtx, repo, stage.directory, descriptor, specification)
		if err != nil {
			return Entry{}, contextError(pullCtx, err)
		}
		record.Files = append(record.Files, fileRecord)
	}
	sort.Slice(record.Files, func(i, j int) bool { return record.Files[i].Name < record.Files[j].Name })
	if err := writeCacheRecord(stage.entry.RecordPath, record); err != nil {
		return Entry{}, err
	}
	if err := makeStageReadOnly(stage.directory, puller.cache.ownerUID); err != nil {
		return Entry{}, err
	}
	if err := validateEntry(pullCtx, stage.entry, puller.cache.ownerUID, puller.limits); err != nil {
		return Entry{}, err
	}
	if err := puller.verify(pullCtx, stage.entry); err != nil {
		return Entry{}, err
	}
	// Revalidate after the verifier so a buggy implementation cannot replace a
	// regular cache component or leave it writable before publication.
	if err := validateEntry(pullCtx, stage.entry, puller.cache.ownerUID, puller.limits); err != nil {
		return Entry{}, err
	}

	entry, concurrent, err := puller.cache.publish(pullCtx, stage, puller.limits)
	if err != nil {
		return Entry{}, contextError(pullCtx, err)
	}
	if concurrent {
		if err := puller.verify(pullCtx, entry); err != nil {
			return Entry{}, err
		}
	}
	installed = true
	return entry, nil
}

func (puller *Puller) verify(ctx context.Context, entry Entry) error {
	if err := puller.verifier.Verify(ctx, entry); err != nil {
		var classified *Error
		if errors.As(err, &classified) {
			return contextError(ctx, err)
		}
		return contextError(ctx, imageError(
			CodeVerificationFailed,
			"The staged image did not pass the required trust verification.",
			"Do not launch the image; inspect redacted verification diagnostics and pull a trusted digest.",
			err,
		))
	}
	return nil
}

func parsePullReference(value string) (registry.Reference, error) {
	if len(value) == 0 || len(value) > 512 || strings.TrimSpace(value) != value || strings.IndexFunc(value, func(r rune) bool {
		return r <= 0x20 || r == 0x7f
	}) >= 0 {
		return registry.Reference{}, errors.New("invalid reference shape")
	}
	parsed, err := registry.ParseReference(value)
	if err != nil || parsed.Reference == "" {
		return registry.Reference{}, errors.New("invalid reference")
	}
	return parsed, nil
}

func digestReference(value string) bool { return strings.HasPrefix(value, "sha256:") }

func validateManifestDescriptor(descriptor ocispec.Descriptor, limits Limits) error {
	if descriptor.MediaType != ocispec.MediaTypeImageManifest ||
		descriptor.Size < 1 || descriptor.Size > limits.MaxManifestBytes ||
		!validSHA256Digest(descriptor.Digest) ||
		len(descriptor.URLs) != 0 || len(descriptor.Data) != 0 ||
		len(descriptor.Annotations) != 0 || descriptor.Platform != nil ||
		descriptor.ArtifactType != "" {
		return imageError(
			CodeManifestInvalid,
			"The resolved OCI manifest descriptor is unsupported or outside its size bound.",
			"Publish an OCI v1 image manifest addressed by a canonical SHA-256 digest.",
			nil,
		)
	}
	return nil
}

func decodeOCIManifest(data []byte, limits Limits) (artifactManifest, error) {
	var wire canonicalManifestWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return artifactManifest{}, imageError(
			CodeManifestInvalid,
			"The OCI manifest is not a closed valid v1 document.",
			"Publish an OCI v1 image manifest with only supported descriptor fields.",
			err,
		)
	}
	canonicalConfigDigest := digest.FromString(canonicalEmptyConfig)
	if decoder.Decode(&struct{}{}) != io.EOF || wire.SchemaVersion != 2 ||
		wire.MediaType != ocispec.MediaTypeImageManifest ||
		wire.Config.MediaType != emptyConfigMediaType ||
		wire.Config.Size != int64(len(canonicalEmptyConfig)) ||
		wire.Config.Digest != canonicalConfigDigest ||
		len(wire.Layers) != len(componentPolicy) || len(wire.Layers) > limits.MaxComponents {
		return artifactManifest{}, imageError(
			CodeManifestInvalid,
			"The OCI manifest structure does not match the bounded private-vm artifact layout.",
			"Publish the exact empty config and one image, manifest, SPDX and provenance layer using only the documented fields.",
			nil,
		)
	}

	document := artifactManifest{
		Config: ocispec.Descriptor{
			MediaType: wire.Config.MediaType,
			Digest:    wire.Config.Digest,
			Size:      wire.Config.Size,
		},
		Layers: make([]ocispec.Descriptor, 0, len(wire.Layers)),
	}
	seen := make(map[string]struct{}, len(wire.Layers))
	for _, layer := range wire.Layers {
		specification, ok := componentPolicy[layer.MediaType]
		if !ok || layer.Size < 1 || !validSHA256Digest(layer.Digest) {
			return artifactManifest{}, imageError(
				CodeManifestInvalid,
				"The OCI artifact contains an unsupported layer descriptor.",
				"Use only the documented private-vm v1 media types and canonical SHA-256 digests.",
				nil,
			)
		}
		if _, duplicate := seen[layer.MediaType]; duplicate {
			return artifactManifest{}, imageError(
				CodeManifestInvalid,
				"The OCI artifact contains a duplicate component type.",
				"Publish exactly one layer for each documented private-vm component.",
				nil,
			)
		}
		seen[layer.MediaType] = struct{}{}
		title := layer.Annotations[ociTitleAnnotation]
		if len(layer.Annotations) != 1 || title != specification.sourceName {
			return artifactManifest{}, imageError(
				CodeManifestInvalid,
				"An OCI component annotation set does not match its fixed cache type.",
				"Use exactly the documented title annotation and base filename for each component.",
				nil,
			)
		}
		maximum := limits.MaxMetadataBytes
		if specification.image {
			maximum = limits.MaxCompressedImageBytes
		}
		if layer.Size > maximum {
			return artifactManifest{}, imageError(
				CodeArtifactLimit,
				"An OCI component exceeds its configured byte limit.",
				"Publish a smaller artifact or raise the bounded policy limit before retrying.",
				nil,
			)
		}
		document.Layers = append(document.Layers, ocispec.Descriptor{
			MediaType:   layer.MediaType,
			Digest:      layer.Digest,
			Size:        layer.Size,
			Annotations: map[string]string{ociTitleAnnotation: title},
		})
	}
	return document, nil
}

func (puller *Puller) installComponent(ctx context.Context, repo Repository, directory string, descriptor ocispec.Descriptor, specification componentSpec) (cacheFileRecord, error) {
	if specification.image {
		return puller.installCompressedImage(ctx, repo, directory, descriptor, specification)
	}
	return puller.installMetadata(ctx, repo, directory, descriptor, specification)
}

func (puller *Puller) installMetadata(ctx context.Context, repo Repository, directory string, descriptor ocispec.Descriptor, specification componentSpec) (cacheFileRecord, error) {
	destination := filepath.Join(directory, specification.installedName)
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return cacheFileRecord{}, imageError(CodeExtractionFailed, "A staged cache file could not be created safely.", "Verify cache ownership and free space, then retry.", err)
	}
	success := false
	defer func() {
		if !success {
			_ = file.Close()
			_ = os.Remove(destination)
		}
	}()

	reader, err := repo.Fetch(ctx, descriptor)
	if err != nil {
		return cacheFileRecord{}, imageError(CodeDownloadFailed, "An OCI component could not be downloaded.", "Retry when the registry is responsive; partial data was removed.", err)
	}
	if nilLike(reader) {
		return cacheFileRecord{}, imageError(CodeDownloadFailed, "An OCI component stream is unavailable.", "Retry the pull; partial data was removed.", nil)
	}

	sourceSize, sourceDigest, err := copyDescriptor(ctx, reader, file, descriptor, puller.limits.MaxMetadataBytes)
	closeErr := reader.Close()
	if err == nil && closeErr != nil {
		err = imageError(CodeDownloadFailed, "An OCI component stream did not close cleanly.", "Retry the pull; partial data was removed.", closeErr)
	}
	if err != nil {
		return cacheFileRecord{}, err
	}
	if err := file.Sync(); err != nil {
		return cacheFileRecord{}, imageError(CodeExtractionFailed, "A staged cache file could not be synchronized.", "Verify cache storage health and free space, then retry.", err)
	}
	if err := file.Close(); err != nil {
		return cacheFileRecord{}, imageError(CodeExtractionFailed, "A staged cache file could not be closed safely.", "Verify cache storage health and retry.", err)
	}
	success = true
	return cacheFileRecord{
		Name: specification.installedName, MediaType: descriptor.MediaType,
		SourceDigest: sourceDigest, InstalledDigest: sourceDigest,
		SourceSizeBytes: sourceSize, InstalledSizeBytes: sourceSize,
	}, nil
}

func (puller *Puller) installCompressedImage(ctx context.Context, repo Repository, directory string, descriptor ocispec.Descriptor, specification componentSpec) (cacheFileRecord, error) {
	compressedPath := filepath.Join(directory, ".image.qcow2.zst.partial")
	compressed, err := os.OpenFile(compressedPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return cacheFileRecord{}, imageError(CodeExtractionFailed, "A hidden compressed-image staging file could not be created safely.", "Verify cache ownership and free space, then retry.", err)
	}
	destination := filepath.Join(directory, specification.installedName)
	var imageFile *os.File
	success := false
	defer func() {
		_ = compressed.Close()
		_ = os.Remove(compressedPath)
		if !success {
			if imageFile != nil {
				_ = imageFile.Close()
			}
			_ = os.Remove(destination)
		}
	}()

	reader, err := repo.Fetch(ctx, descriptor)
	if err != nil {
		return cacheFileRecord{}, imageError(CodeDownloadFailed, "The compressed image could not be downloaded.", "Retry when the registry is responsive; partial data was removed.", err)
	}
	if nilLike(reader) {
		return cacheFileRecord{}, imageError(CodeDownloadFailed, "The compressed image stream is unavailable.", "Retry the pull; partial data was removed.", nil)
	}

	// IMG-003 depends on this order: no untrusted compressed byte reaches the
	// decoder until the complete source is bounded and matches its resolved OCI
	// descriptor. The same private file description is rewound after hashing,
	// preventing a pathname substitution between verification and decode.
	sourceSize, sourceDigest, copyErr := copyDescriptor(ctx, reader, compressed, descriptor, puller.limits.MaxCompressedImageBytes)
	closeErr := reader.Close()
	if copyErr != nil {
		return cacheFileRecord{}, copyErr
	}
	if closeErr != nil {
		return cacheFileRecord{}, imageError(CodeDownloadFailed, "The compressed image stream did not close cleanly.", "Retry the pull; partial data was removed.", closeErr)
	}
	if err := compressed.Sync(); err != nil {
		return cacheFileRecord{}, imageError(CodeExtractionFailed, "The verified compressed image could not be synchronized.", "Verify cache storage health and free space, then retry.", err)
	}
	if _, err := compressed.Seek(0, io.SeekStart); err != nil {
		return cacheFileRecord{}, imageError(CodeExtractionFailed, "The verified compressed image could not be rewound safely.", "Verify cache storage health and retry.", err)
	}

	imageFile, err = os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return cacheFileRecord{}, imageError(CodeExtractionFailed, "A staged image cache file could not be created safely.", "Verify cache ownership and free space, then retry.", err)
	}
	installedSize, installedDigest, err := puller.decompress(ctx, compressed, imageFile, puller.limits.MaxUncompressedImageBytes)
	if err != nil {
		return cacheFileRecord{}, err
	}
	if err := imageFile.Sync(); err != nil {
		return cacheFileRecord{}, imageError(CodeExtractionFailed, "The staged image cache file could not be synchronized.", "Verify cache storage health and free space, then retry.", err)
	}
	if err := imageFile.Close(); err != nil {
		return cacheFileRecord{}, imageError(CodeExtractionFailed, "The staged image cache file could not be closed safely.", "Verify cache storage health and retry.", err)
	}
	imageFile = nil
	if err := compressed.Close(); err != nil {
		return cacheFileRecord{}, imageError(CodeExtractionFailed, "The verified compressed-image staging file could not be closed safely.", "Verify cache storage health and retry.", err)
	}
	if err := os.Remove(compressedPath); err != nil {
		return cacheFileRecord{}, imageError(CodeExtractionFailed, "The verified compressed-image staging file could not be removed.", "Verify cache ownership and retry before publishing the entry.", err)
	}
	success = true
	return cacheFileRecord{
		Name: specification.installedName, MediaType: descriptor.MediaType,
		SourceDigest: sourceDigest, InstalledDigest: installedDigest,
		SourceSizeBytes: sourceSize, InstalledSizeBytes: installedSize,
	}, nil
}

func fetchBytes(ctx context.Context, repo Repository, descriptor ocispec.Descriptor, maximum int64) ([]byte, error) {
	reader, err := repo.Fetch(ctx, descriptor)
	if err != nil {
		return nil, imageError(CodeDownloadFailed, "An OCI manifest or metadata object could not be downloaded.", "Retry when the registry is responsive; partial data was removed.", err)
	}
	if nilLike(reader) {
		return nil, imageError(CodeDownloadFailed, "An OCI manifest or metadata stream is unavailable.", "Retry the pull; partial data was removed.", nil)
	}
	data, copyErr := readDescriptor(ctx, reader, descriptor, maximum)
	closeErr := reader.Close()
	if copyErr != nil {
		return nil, copyErr
	}
	if closeErr != nil {
		return nil, imageError(CodeDownloadFailed, "An OCI response stream did not close cleanly.", "Retry the pull; partial data was removed.", closeErr)
	}
	return data, nil
}

func fetchCanonicalConfig(ctx context.Context, repo Repository, descriptor ocispec.Descriptor) error {
	data, err := fetchBytes(ctx, repo, descriptor, int64(len(canonicalEmptyConfig)))
	if err != nil {
		return err
	}
	if !bytes.Equal(data, []byte(canonicalEmptyConfig)) {
		return imageError(
			CodeManifestInvalid,
			"The OCI config blob is not the canonical private-vm empty config.",
			"Publish the exact two-byte JSON object required by the frozen v1 artifact layout.",
			nil,
		)
	}
	return nil
}

func readDescriptor(ctx context.Context, reader io.Reader, descriptor ocispec.Descriptor, maximum int64) ([]byte, error) {
	if descriptor.Size < 0 || descriptor.Size > maximum {
		return nil, imageError(CodeArtifactLimit, "An OCI object exceeds its configured byte limit.", "Use a bounded artifact that matches the documented media layout.", nil)
	}
	buffer := bytes.NewBuffer(make([]byte, 0, descriptor.Size))
	if _, _, err := copyDescriptor(ctx, io.NopCloser(reader), buffer, descriptor, maximum); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func copyDescriptor(ctx context.Context, reader io.Reader, writer io.Writer, descriptor ocispec.Descriptor, maximum int64) (int64, string, error) {
	if descriptor.Size < 0 || descriptor.Size > maximum {
		return 0, "", imageError(CodeArtifactLimit, "An OCI object exceeds its configured byte limit.", "Use a bounded artifact that matches the documented media layout.", nil)
	}
	hasher := sha256.New()
	written, err := copyBounded(ctx, io.TeeReader(reader, hasher), writer, descriptor.Size)
	if err != nil {
		return 0, "", err
	}
	actual := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if written != descriptor.Size || actual != descriptor.Digest.String() {
		return 0, "", imageError(CodeDigestMismatch, "An OCI object did not match its resolved descriptor.", "Do not use the artifact; retry by immutable digest.", nil)
	}
	return written, actual, nil
}

func decompressZstd(ctx context.Context, reader io.Reader, writer io.Writer, maximum int64) (int64, string, error) {
	decoder, err := zstd.NewReader(reader, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(256<<20))
	if err != nil {
		return 0, "", imageError(CodeExtractionFailed, "The verified compressed image could not be decoded.", "Publish a valid bounded zstd-compressed QCOW2 image.", err)
	}
	defer decoder.Close()
	installedHasher := sha256.New()
	installedSize, copyErr := copyWithContext(ctx, io.MultiWriter(writer, installedHasher), io.LimitReader(decoder, maximum+1))
	if copyErr != nil {
		return 0, "", imageError(CodeExtractionFailed, "The verified compressed image could not be decoded completely.", "Publish a valid bounded zstd-compressed QCOW2 image.", copyErr)
	}
	if installedSize > maximum {
		return 0, "", imageError(CodeArtifactLimit, "The installed image exceeds its configured byte limit.", "Publish a smaller bounded QCOW2 image.", nil)
	}
	if installedSize < 1 {
		return 0, "", imageError(CodeExtractionFailed, "The compressed image produced an empty cache file.", "Publish a non-empty valid QCOW2 image.", nil)
	}
	return installedSize, "sha256:" + hex.EncodeToString(installedHasher.Sum(nil)), nil
}

func copyBounded(ctx context.Context, reader io.Reader, writer io.Writer, maximum int64) (int64, error) {
	written, err := copyWithContext(ctx, writer, io.LimitReader(reader, maximum+1))
	if err != nil {
		return 0, imageError(CodeDownloadFailed, "An OCI object could not be read completely.", "Retry the pull; partial data was removed.", err)
	}
	if written > maximum {
		return 0, imageError(CodeArtifactLimit, "An extracted OCI component exceeds its configured byte limit.", "Publish a smaller bounded artifact.", nil)
	}
	return written, nil
}

func copyWithContext(ctx context.Context, writer io.Writer, reader io.Reader) (int64, error) {
	buffer := make([]byte, 1<<20)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		count, readErr := reader.Read(buffer)
		if count > 0 {
			written, writeErr := writer.Write(buffer[:count])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != count {
				return total, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
		if count == 0 {
			return total, io.ErrNoProgress
		}
	}
}

func validSHA256Digest(value digest.Digest) bool {
	if value.Algorithm() != digest.SHA256 || len(value.Encoded()) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value.Encoded())
	return err == nil && strings.ToLower(value.Encoded()) == value.Encoded()
}

func safeDigest(value string) string {
	return strings.TrimPrefix(value, "sha256:")
}

func digestPath(root, value string) string {
	return filepath.Join(root, "sha256", safeDigest(value))
}

func parseDigest(value string) (digest.Digest, error) {
	parsed, err := digest.Parse(value)
	if err != nil || !validSHA256Digest(parsed) {
		return "", fmt.Errorf("invalid sha256 digest")
	}
	return parsed, nil
}

func nilLike(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
