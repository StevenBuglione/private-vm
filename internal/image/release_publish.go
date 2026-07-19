package image

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	maxRegistryTokenBytes = 64 << 10
	releasePublishTimeout = 45 * time.Minute
)

// PublishOptions binds one already-prepared release to one canonical version tag.
// Token is read through protected storage and is never serialized or logged.
type PublishOptions struct {
	Directory      string
	ProvenancePath string
	Repository     string
	ReleaseTag     string
	Username       string
	Token          *secret.Bytes
}

// PublishResult reports only public immutable artifact identity.
type PublishResult struct {
	Repository     string `json:"repository"`
	ReleaseTag     string `json:"release_tag"`
	ManifestDigest string `json:"manifest_digest"`
}

type pushRepository interface {
	Resolve(context.Context, string) (ocispec.Descriptor, error)
	Push(context.Context, ocispec.Descriptor, io.Reader) error
	PushReference(context.Context, ocispec.Descriptor, io.Reader, string) error
}

type pushRepositoryFactory interface {
	Open(string, string, string, *secret.Bytes) (pushRepository, error)
}

type orasPushFactory struct{}

func (orasPushFactory) Open(repository, tag, username string, token *secret.Bytes) (pushRepository, error) {
	repo, err := remote.NewRepository(repository)
	if err != nil {
		return nil, err
	}
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	client := &http.Client{
		Timeout:   releasePublishTimeout,
		Transport: conditionalTagTransport{base: baseTransport, repository: repo.Reference.Repository, tag: tag},
	}
	repo.Client = &auth.Client{
		Client: client,
		Cache:  nil,
		Credential: func(ctx context.Context, hostport string) (auth.Credential, error) {
			if err := ctx.Err(); err != nil {
				return auth.EmptyCredential, err
			}
			if hostport != repo.Reference.Registry {
				return auth.EmptyCredential, nil
			}
			var credential auth.Credential
			err := token.WithReader(func(reader io.Reader) error {
				value, err := io.ReadAll(io.LimitReader(reader, maxRegistryTokenBytes+1))
				if err != nil || len(value) == 0 || len(value) > maxRegistryTokenBytes {
					clear(value)
					return errors.New("registry token is outside its bound")
				}
				credential = auth.Credential{Username: username, Password: string(value)}
				clear(value)
				return nil
			})
			if err != nil {
				return auth.EmptyCredential, err
			}
			return credential, nil
		},
	}
	repo.MaxMetadataBytes = DefaultLimits().MaxManifestBytes
	repo.ManifestMediaTypes = []string{ocispec.MediaTypeImageManifest}
	return repo, nil
}

// conditionalTagTransport makes the final mutable-name operation conditional.
// Digest manifest and blob PUTs are unaffected. Independent controls are the
// protected immutable Git release tag, tag-only workflow, single protected
// packages:write authority, workflow concurrency and the post-write recheck;
// GHCR package tags themselves are not claimed to be server-side immutable.
type conditionalTagTransport struct {
	base       http.RoundTripper
	repository string
	tag        string
}

func (transport conditionalTagTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodPut && request.URL != nil &&
		request.URL.EscapedPath() == "/v2/"+escapeRepositoryPath(transport.repository)+"/manifests/"+url.PathEscape(transport.tag) {
		copy := request.Clone(request.Context())
		copy.Header = request.Header.Clone()
		copy.Header.Set("If-None-Match", "*")
		request = copy
	}
	return transport.base.RoundTrip(request)
}

func escapeRepositoryPath(value string) string {
	parts := strings.Split(value, "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/")
}

type preparedPublication struct {
	receipt          ReleaseReceipt
	manifest         Manifest
	manifestBytes    []byte
	layers           []releaseLayer
	ociBytes         []byte
	ociDescriptor    ocispec.Descriptor
	removeProvenance bool
}

type releaseLayer struct {
	descriptor ocispec.Descriptor
	path       string
}

// PublishRelease locally verifies the complete official Sigstore bundle before
// any registry mutation, uploads content-addressed blobs, uploads the manifest
// by digest, and creates the sole SemVer tag only after all prior operations
// succeed. Existing tags always fail before a push, even if their digest agrees.
func PublishRelease(ctx context.Context, options PublishOptions) (PublishResult, error) {
	return publishRelease(ctx, options, orasPushFactory{}, nil)
}

func publishRelease(ctx context.Context, options PublishOptions, factory pushRepositoryFactory, verifier Verifier) (result PublishResult, returnedErr error) {
	if !filepath.IsAbs(options.Directory) || filepath.Clean(options.Directory) != options.Directory ||
		!filepath.IsAbs(options.ProvenancePath) || filepath.Clean(options.ProvenancePath) != options.ProvenancePath ||
		options.Token == nil || !boundedText(options.Username, 1, 128) {
		return PublishResult{}, releaseInvalid("The release publication input is incomplete or unsafe.", nil)
	}
	resolvedDirectory, err := filepath.EvalSymlinks(options.Directory)
	directoryInfo, statErr := os.Lstat(options.Directory)
	if err != nil || statErr != nil || resolvedDirectory != options.Directory || !directoryInfo.IsDir() || directoryInfo.Mode().Perm()&0o022 != 0 || fileUID(directoryInfo) != os.Geteuid() {
		return PublishResult{}, releaseInvalid("The prepared release directory is not a real owner-controlled directory.", errors.Join(err, statErr))
	}
	defer func() {
		if cleanupErr := removeOwnedReleaseTree(options.Directory); cleanupErr != nil {
			result = PublishResult{}
			returnedErr = imageError(
				CodeReleasePublishFailed,
				"The owner-controlled release staging directory could not be removed completely.",
				"Inspect the published tag by digest before retrying; remove only the exact verified staging directory.",
				errors.Join(returnedErr, cleanupErr),
			)
		}
	}()
	publishCtx, cancel := context.WithTimeout(ctx, releasePublishTimeout)
	defer cancel()
	publication, err := loadPreparedPublication(publishCtx, options)
	if err != nil {
		return PublishResult{}, contextError(publishCtx, err)
	}
	if publication.removeProvenance {
		defer os.Remove(filepath.Join(options.Directory, "provenance.json"))
	}
	if verifier == nil {
		policy := CompatibilityPolicy{
			Role: publication.receipt.Role, Bundle: releaseReceiptBundle(publication.receipt), HostArchitecture: "amd64",
			GuestAPIMajor: 1, GuestAPIMinor: 0, MinimumGuestAPIMinor: 0,
			HostQEMUVersion: "10.2.4", NixOSVersion: frozenNixOSVersion, Limits: DefaultVerificationLimits(),
		}
		verifier, err = NewOfficialVerifier(policy)
		if err != nil {
			return PublishResult{}, err
		}
	}
	if err := verifyPreparedPublication(publishCtx, publication, verifier); err != nil {
		return PublishResult{}, err
	}
	repo, err := factory.Open(options.Repository, options.ReleaseTag, options.Username, options.Token)
	if err != nil || nilLike(repo) {
		return PublishResult{}, releasePublishFailed("The target OCI repository could not be opened.", err)
	}
	if _, err := repo.Resolve(publishCtx, options.ReleaseTag); err == nil {
		return PublishResult{}, releaseConflict()
	} else if !errors.Is(err, errdef.ErrNotFound) {
		return PublishResult{}, contextError(publishCtx, releasePublishFailed("The release version tag could not be checked safely.", err))
	}
	configDescriptor := content.NewDescriptorFromBytes(emptyConfigMediaType, []byte(canonicalEmptyConfig))
	if err := pushBytes(publishCtx, repo, configDescriptor, []byte(canonicalEmptyConfig)); err != nil {
		return PublishResult{}, err
	}
	for _, layer := range publication.layers {
		if err := pushFile(publishCtx, repo, layer.descriptor, layer.path); err != nil {
			return PublishResult{}, err
		}
	}
	if err := pushBytes(publishCtx, repo, publication.ociDescriptor, publication.ociBytes); err != nil {
		return PublishResult{}, err
	}
	// Recheck immediately before the only tag write. The repository transport
	// adds If-None-Match; protected workflow concurrency and sole packages:write
	// authority prevent competing official publishers. No GHCR tag-immutability
	// feature is assumed.
	if _, err := repo.Resolve(publishCtx, options.ReleaseTag); err == nil {
		return PublishResult{}, releaseConflict()
	} else if !errors.Is(err, errdef.ErrNotFound) {
		return PublishResult{}, contextError(publishCtx, releasePublishFailed("The release tag could not be rechecked before publication.", err))
	}
	if err := repo.PushReference(publishCtx, publication.ociDescriptor, bytes.NewReader(publication.ociBytes), options.ReleaseTag); err != nil {
		return PublishResult{}, contextError(publishCtx, releasePublishFailed("The release version tag could not be created conditionally.", err))
	}
	resolved, err := repo.Resolve(publishCtx, options.ReleaseTag)
	if err != nil || resolved.Digest != publication.ociDescriptor.Digest {
		return PublishResult{}, contextError(publishCtx, releasePublishFailed("The published tag did not resolve to the exact uploaded OCI manifest digest.", err))
	}
	return PublishResult{Repository: options.Repository, ReleaseTag: options.ReleaseTag, ManifestDigest: publication.ociDescriptor.Digest.String()}, nil
}

func loadPreparedPublication(ctx context.Context, options PublishOptions) (preparedPublication, error) {
	receiptBytes, err := readBoundedRegular(filepath.Join(options.Directory, "release-receipt.json"), maxCacheRecordBytes)
	if err != nil {
		return preparedPublication{}, err
	}
	var receipt ReleaseReceipt
	decoder := json.NewDecoder(bytes.NewReader(receiptBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !validReleaseReceipt(receipt) ||
		receipt.Repository != options.Repository || receipt.ReleaseTag != options.ReleaseTag {
		return preparedPublication{}, releaseInvalid("The prepared release receipt is malformed or does not bind this publication.", err)
	}
	manifestBytes, err := readBoundedRegular(filepath.Join(options.Directory, "manifest.json"), DefaultVerificationLimits().MaxManifestBytes)
	if err != nil || digestBytes(manifestBytes) != receipt.ManifestDigest {
		return preparedPublication{}, releaseInvalid("The prepared manifest does not match its release receipt.", err)
	}
	manifest, err := decodeManifest(manifestBytes, DefaultVerificationLimits().MaxJSONDepth)
	if err != nil || manifest.ImageDigest != receipt.ImageDigest || manifest.SBOMDigest != receipt.SBOMDigest {
		return preparedPublication{}, releaseInvalid("The prepared manifest identity does not match its release receipt.", err)
	}
	sbomPath := filepath.Join(options.Directory, "sbom.spdx.json")
	sbomDigest, sbomSize, err := hashPath(ctx, sbomPath, DefaultVerificationLimits().MaxSBOMBytes)
	if err != nil || sbomDigest != receipt.SBOMDigest {
		return preparedPublication{}, releaseInvalid("The prepared SPDX document does not match its release receipt.", err)
	}
	imagePath := filepath.Join(options.Directory, "image.qcow2.zst")
	imageDigest, imageSize, err := hashPath(ctx, imagePath, maxReleaseCompressedBytes)
	if err != nil || imageDigest != receipt.ImageDigest || imageSize != receipt.CompressedSizeBytes {
		return preparedPublication{}, releaseInvalid("The compressed QCOW2 does not match its release receipt.", err)
	}
	compressed, _, err := openBoundedRegular(imagePath, maxReleaseCompressedBytes)
	if err != nil {
		return preparedPublication{}, releaseInvalid("The compressed QCOW2 could not be reopened for local verification.", err)
	}
	header := newHeaderCapture(104)
	uncompressedSize, uncompressedDigest, decompressErr := decompressZstd(ctx, compressed, header, maxReleaseUncompressedSize)
	closeErr := compressed.Close()
	if decompressErr != nil || closeErr != nil || uncompressedSize != receipt.UncompressedSizeBytes ||
		strings.TrimPrefix(uncompressedDigest, "sha256:") != receipt.UncompressedSHA256 {
		return preparedPublication{}, releaseInvalid("The compressed QCOW2 does not reproduce the receipt's bounded uncompressed identity.", errors.Join(decompressErr, closeErr))
	}
	virtualSize, err := validateQCOW2Header(header.Bytes(), uncompressedSize)
	if err != nil || virtualSize != receipt.VirtualSizeBytes {
		return preparedPublication{}, releaseInvalid("The compressed QCOW2 does not reproduce the validated virtual-size contract.", err)
	}
	provenanceBytes, err := readBoundedRegular(options.ProvenancePath, DefaultVerificationLimits().MaxProvenanceBytes)
	if err != nil {
		return preparedPublication{}, err
	}
	provenancePath := filepath.Join(options.Directory, "provenance.json")
	removeProvenance := false
	if options.ProvenancePath != provenancePath {
		if err := writeExclusive(provenancePath, provenanceBytes, 0o600); err != nil {
			return preparedPublication{}, err
		}
		removeProvenance = true
	}
	components := []struct {
		mediaType string
		path      string
		name      string
		digest    string
		size      int64
	}{
		{MediaTypeQCOW2Zstd, imagePath, "image.qcow2.zst", imageDigest, imageSize},
		{MediaTypeManifest, filepath.Join(options.Directory, "manifest.json"), "manifest.json", digestBytes(manifestBytes), int64(len(manifestBytes))},
		{MediaTypeSBOM, sbomPath, "sbom.spdx.json", sbomDigest, sbomSize},
		{MediaTypeProvenance, provenancePath, "provenance.json", digestBytes(provenanceBytes), int64(len(provenanceBytes))},
	}
	layers := make([]releaseLayer, 0, len(components))
	wireLayers := make([]canonicalLayerWire, 0, len(components))
	for _, component := range components {
		descriptor := ocispec.Descriptor{MediaType: component.mediaType, Digest: digest.Digest(component.digest), Size: component.size, Annotations: map[string]string{ociTitleAnnotation: component.name}}
		layers = append(layers, releaseLayer{descriptor: descriptor, path: component.path})
		wireLayers = append(wireLayers, canonicalLayerWire{MediaType: descriptor.MediaType, Digest: descriptor.Digest, Size: descriptor.Size, Annotations: descriptor.Annotations})
	}
	configDescriptor := content.NewDescriptorFromBytes(emptyConfigMediaType, []byte(canonicalEmptyConfig))
	wire := canonicalManifestWire{SchemaVersion: 2, MediaType: ocispec.MediaTypeImageManifest,
		Config: canonicalDescriptorWire{MediaType: configDescriptor.MediaType, Digest: configDescriptor.Digest, Size: configDescriptor.Size}, Layers: wireLayers}
	ociBytes, err := json.Marshal(wire)
	if err != nil {
		return preparedPublication{}, releaseInvalid("The exact OCI manifest could not be encoded.", err)
	}
	descriptor := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, ociBytes)
	return preparedPublication{receipt: receipt, manifest: manifest, manifestBytes: manifestBytes, layers: layers, ociBytes: ociBytes, ociDescriptor: descriptor, removeProvenance: removeProvenance}, nil
}

type headerCapture struct {
	value   []byte
	maximum int
}

func newHeaderCapture(maximum int) *headerCapture {
	return &headerCapture{value: make([]byte, 0, maximum), maximum: maximum}
}

func (capture *headerCapture) Write(value []byte) (int, error) {
	if len(capture.value) < capture.maximum {
		remaining := capture.maximum - len(capture.value)
		if remaining > len(value) {
			remaining = len(value)
		}
		capture.value = append(capture.value, value[:remaining]...)
	}
	return len(value), nil
}

func (capture *headerCapture) Bytes() []byte { return append([]byte(nil), capture.value...) }

func verifyPreparedPublication(ctx context.Context, publication preparedPublication, verifier Verifier) error {
	record := cacheRecord{SchemaVersion: 1, OCIManifestDigest: publication.ociDescriptor.Digest.String()}
	for _, layer := range publication.layers {
		installedDigest, installedSize := layer.descriptor.Digest.String(), layer.descriptor.Size
		name := componentPolicy[layer.descriptor.MediaType].installedName
		if layer.descriptor.MediaType == MediaTypeQCOW2Zstd {
			installedDigest = "sha256:" + publication.receipt.UncompressedSHA256
			installedSize = publication.receipt.UncompressedSizeBytes
		}
		record.Files = append(record.Files, cacheFileRecord{Name: name, MediaType: layer.descriptor.MediaType,
			SourceDigest: layer.descriptor.Digest.String(), InstalledDigest: installedDigest,
			SourceSizeBytes: layer.descriptor.Size, InstalledSizeBytes: installedSize})
	}
	recordPath := filepath.Join(filepath.Dir(publication.layers[0].path), ".release-cache-entry.json")
	_ = os.Remove(recordPath)
	if err := writeCacheRecord(recordPath, record); err != nil {
		return err
	}
	defer os.Remove(recordPath)
	directory := filepath.Dir(publication.layers[0].path)
	entry := Entry{ManifestDigest: publication.ociDescriptor.Digest.String(), Directory: directory,
		ImagePath: filepath.Join(directory, "image.qcow2"), ManifestPath: filepath.Join(directory, "manifest.json"),
		SBOMPath: filepath.Join(directory, "sbom.spdx.json"), ProvenancePath: filepath.Join(directory, "provenance.json"), RecordPath: recordPath}
	return verifier.Verify(ctx, entry)
}

func validReleaseReceipt(receipt ReleaseReceipt) bool {
	if receipt.SchemaVersion != releaseSchemaVersion || receipt.Project != "private-vm" || receipt.SourceRepository != officialRepository ||
		receipt.Workflow != officialWorkflow || receipt.SourceRef != "refs/tags/"+receipt.ReleaseTag ||
		!officialReleaseRefPattern.MatchString(receipt.SourceRef) || !commitPattern.MatchString(receipt.SourceCommit) ||
		!validDigest(receipt.ImageDigest) || !validHex(receipt.UncompressedSHA256, 32) || !validDigest(receipt.SBOMDigest) ||
		!validDigest(receipt.ManifestDigest) || receipt.CompressedSizeBytes < 1 || receipt.CompressedSizeBytes > maxReleaseCompressedBytes ||
		receipt.UncompressedSizeBytes < 1 || receipt.UncompressedSizeBytes > maxReleaseUncompressedSize ||
		receipt.VirtualSizeBytes < receipt.UncompressedSizeBytes || receipt.VirtualSizeBytes > maxReleaseUncompressedSize ||
		len(receipt.Files) != 4 {
		return false
	}
	bundle := ""
	if receipt.Bundle != nil {
		bundle = *receipt.Bundle
	}
	return validRoleBundle(receipt.Role, bundle) && receipt.Repository == "ghcr.io/stevenbuglione/private-vm/"+releaseImageName(receipt.Role, bundle) &&
		equalStrings(receipt.Files, []string{"image.qcow2.zst", "manifest.json", "sbom.spdx.json", "predicate.json"})
}

func releaseReceiptBundle(receipt ReleaseReceipt) string {
	if receipt.Bundle == nil {
		return ""
	}
	return *receipt.Bundle
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	file, _, err := openBoundedRegular(path, maximum)
	if err != nil {
		return nil, releaseInvalid("A release component has an unsafe type, ownership or byte size.", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, releaseInvalid("A release component could not be read within its bound.", err)
	}
	return data, nil
}

func pushBytes(ctx context.Context, repository pushRepository, descriptor ocispec.Descriptor, data []byte) error {
	if err := repository.Push(ctx, descriptor, bytes.NewReader(data)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return contextError(ctx, releasePublishFailed("A content-addressed release component could not be uploaded.", err))
	}
	return nil
}

func pushFile(ctx context.Context, repository pushRepository, descriptor ocispec.Descriptor, path string) error {
	actualDigest, actualSize, err := hashPath(ctx, path, descriptor.Size)
	if err != nil || actualSize != descriptor.Size || digest.Digest(actualDigest) != descriptor.Digest {
		return releasePublishFailed("A release component changed after local verification.", err)
	}
	file, info, err := openBoundedRegular(path, descriptor.Size)
	if err != nil {
		return releasePublishFailed("A locally verified release component could not be reopened for upload.", err)
	}
	defer file.Close()
	if info.Size() != descriptor.Size {
		return releasePublishFailed("A release component size changed after local verification.", nil)
	}
	if err := repository.Push(ctx, descriptor, io.LimitReader(file, descriptor.Size+1)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return contextError(ctx, releasePublishFailed("A content-addressed release component could not be uploaded.", err))
	}
	return nil
}

func releaseConflict() error {
	return imageError(CodeReleaseConflict, "The release version tag already exists.", "Never overwrite a package version tag; create a new protected Git SemVer or release-candidate tag.", nil)
}

func releasePublishFailed(message string, cause error) error {
	return imageError(CodeReleasePublishFailed, message, "Retry only after confirming the tag is absent; content-addressed partial blobs are safe and no tag was published.", cause)
}

var _ pushRepositoryFactory = orasPushFactory{}
var _ http.RoundTripper = conditionalTagTransport{}
