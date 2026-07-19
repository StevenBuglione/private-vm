package image

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type fakeRepositoryFactory struct {
	repository *fakeRepository
	opened     string
	err        error
}

func (factory *fakeRepositoryFactory) Open(repository string) (Repository, error) {
	factory.opened = repository
	return factory.repository, factory.err
}

type fakeRepository struct {
	mu              sync.Mutex
	manifest        ocispec.Descriptor
	blobs           map[string][]byte
	calls           []string
	resolveErr      error
	resolveWait     bool
	fetchErrDigest  string
	fetchWaitDigest string
	fetchNilDigest  string
	closeErrDigest  string
	fetchStarted    chan struct{}
}

func (repository *fakeRepository) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	repository.mu.Lock()
	repository.calls = append(repository.calls, "resolve:"+reference)
	repository.mu.Unlock()
	if repository.resolveWait {
		<-ctx.Done()
		return ocispec.Descriptor{}, ctx.Err()
	}
	return repository.manifest, repository.resolveErr
}

func (repository *fakeRepository) Fetch(ctx context.Context, descriptor ocispec.Descriptor) (io.ReadCloser, error) {
	repository.mu.Lock()
	repository.calls = append(repository.calls, "fetch:"+descriptor.Digest.String())
	repository.mu.Unlock()
	if descriptor.Digest.String() == repository.fetchWaitDigest {
		if repository.fetchStarted != nil {
			close(repository.fetchStarted)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if descriptor.Digest.String() == repository.fetchErrDigest {
		return nil, errors.New("registry-private-sentinel")
	}
	if descriptor.Digest.String() == repository.fetchNilDigest {
		var reader *typedNilReader
		return reader, nil
	}
	data, ok := repository.blobs[descriptor.Digest.String()]
	if !ok {
		return nil, errors.New("missing fixture blob")
	}
	reader := io.NopCloser(bytes.NewReader(data))
	if descriptor.Digest.String() == repository.closeErrDigest {
		return closeErrorReader{ReadCloser: reader}, nil
	}
	return reader, nil
}

func (repository *fakeRepository) callLog() []string {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]string(nil), repository.calls...)
}

type closeErrorReader struct{ io.ReadCloser }

func (closeErrorReader) Close() error { return errors.New("close-private-sentinel") }

type typedNilReader struct{}

func (*typedNilReader) Read([]byte) (int, error) { return 0, io.EOF }
func (*typedNilReader) Close() error             { return nil }

type artifactFixture struct {
	repository  *fakeRepository
	image       []byte
	descriptors map[string]ocispec.Descriptor
}

func newArtifactFixture(t *testing.T) artifactFixture {
	t.Helper()
	image := []byte("QFI\xfbprivate-vm-test-image")
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	compressed := encoder.EncodeAll(image, nil)
	encoder.Close()

	components := []struct {
		mediaType string
		title     string
		data      []byte
	}{
		{MediaTypeQCOW2Zstd, "image.qcow2.zst", compressed},
		{MediaTypeManifest, "manifest.json", []byte(`{"schema_version":1,"project":"private-vm"}`)},
		{MediaTypeSBOM, "sbom.spdx.json", []byte(`{"spdxVersion":"SPDX-2.3"}`)},
		{MediaTypeProvenance, "provenance.json", []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json"}`)},
	}
	blobs := make(map[string][]byte)
	descriptors := make(map[string]ocispec.Descriptor)
	layers := make([]ocispec.Descriptor, 0, len(components))
	for _, component := range components {
		descriptor := descriptorFor(component.mediaType, component.data)
		descriptor.Annotations = map[string]string{ociTitleAnnotation: component.title}
		layers = append(layers, descriptor)
		blobs[descriptor.Digest.String()] = component.data
		descriptors[component.mediaType] = descriptor
	}
	configData := []byte("{}")
	config := descriptorFor("application/vnd.oci.empty.v1+json", configData)
	blobs[config.Digest.String()] = configData
	manifestData, err := json.Marshal(makeManifest(config, layers))
	if err != nil {
		t.Fatal(err)
	}
	manifest := descriptorFor(ocispec.MediaTypeImageManifest, manifestData)
	blobs[manifest.Digest.String()] = manifestData
	return artifactFixture{
		repository:  &fakeRepository{manifest: manifest, blobs: blobs},
		image:       image,
		descriptors: descriptors,
	}
}

func descriptorFor(mediaType string, data []byte) ocispec.Descriptor {
	return ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
}

func makeManifest(config ocispec.Descriptor, layers []ocispec.Descriptor) ocispec.Manifest {
	return ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    config,
		Layers:    layers,
	}
}

func newTestPuller(t *testing.T, fixture artifactFixture, verifier Verifier, mutateLimits func(*Limits)) (*Puller, *Cache) {
	t.Helper()
	cache, err := NewCache(t.TempDir(), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	registerCacheCleanup(t, cache)
	limits := DefaultLimits()
	limits.Timeout = time.Second
	if mutateLimits != nil {
		mutateLimits(&limits)
	}
	puller, err := NewPuller(&fakeRepositoryFactory{repository: fixture.repository}, cache, verifier, limits)
	if err != nil {
		t.Fatal(err)
	}
	return puller, cache
}

func acceptingVerifier(t *testing.T, expected []byte) Verifier {
	t.Helper()
	return VerificationFunc(func(_ context.Context, entry Entry) error {
		actual, err := os.ReadFile(entry.ImagePath)
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, expected) {
			return errors.New("unexpected extracted image")
		}
		return nil
	})
}

func TestPullResolvesTagBeforeBoundedAtomicInstall(t *testing.T) {
	fixture := newArtifactFixture(t)
	puller, cache := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), nil)

	entry, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
	if err != nil {
		t.Fatal(err)
	}
	expectedDirectory := filepath.Join(cache.root, "sha256", fixture.repository.manifest.Digest.Encoded())
	if entry.Directory != expectedDirectory || entry.ManifestDigest != fixture.repository.manifest.Digest.String() {
		t.Fatalf("entry is not digest addressed: %#v", entry)
	}
	calls := fixture.repository.callLog()
	if len(calls) == 0 || calls[0] != "resolve:stable" {
		t.Fatalf("remote layer access occurred before tag resolution: %v", calls)
	}
	if data, err := os.ReadFile(entry.ImagePath); err != nil || !bytes.Equal(data, fixture.image) {
		t.Fatalf("image extraction mismatch: data=%q err=%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(entry.Directory, "image.qcow2.zst")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("compressed intermediate remained in runnable cache: %v", err)
	}
	for _, path := range []string{entry.ImagePath, entry.ManifestPath, entry.SBOMPath, entry.ProvenancePath, entry.RecordPath} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
			t.Fatalf("unsafe installed file %q: mode=%v err=%v", filepath.Base(path), infoMode(info), err)
		}
	}
	info, err := os.Lstat(entry.Directory)
	if err != nil || info.Mode().Perm() != 0o555 {
		t.Fatalf("unsafe installed directory: mode=%v err=%v", infoMode(info), err)
	}
	partials, err := filepath.Glob(filepath.Join(cache.root, "sha256", ".partial-*"))
	if err != nil || len(partials) != 0 {
		t.Fatalf("partial staging directories remain: %v err=%v", partials, err)
	}
}

func TestPullRevalidatesDigestCacheWithoutLayerDownload(t *testing.T) {
	fixture := newArtifactFixture(t)
	verifyCount := 0
	verifier := VerificationFunc(func(context.Context, Entry) error {
		verifyCount++
		return nil
	})
	puller, _ := newTestPuller(t, fixture, verifier, nil)
	if _, err := puller.Pull(context.Background(), "registry.example/repo/image:stable"); err != nil {
		t.Fatal(err)
	}
	fixture.repository.mu.Lock()
	fixture.repository.calls = nil
	fixture.repository.mu.Unlock()
	if _, err := puller.Pull(context.Background(), "registry.example/repo/image:stable"); err != nil {
		t.Fatal(err)
	}
	if calls := fixture.repository.callLog(); !reflect.DeepEqual(calls, []string{"resolve:stable"}) {
		t.Fatalf("cache hit fetched mutable or layer data: %v", calls)
	}
	if verifyCount != 2 {
		t.Fatalf("cache hit skipped trust verification: count=%d", verifyCount)
	}
}

func TestPullNeverPublishesPartialOrUnverifiedData(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*artifactFixture)
		verifier Verifier
		wantCode ErrorCode
	}{
		{
			name: "component digest mismatch",
			mutate: func(fixture *artifactFixture) {
				descriptor := fixture.descriptors[MediaTypeManifest]
				fixture.repository.blobs[descriptor.Digest.String()] = []byte("modified")
			},
			wantCode: CodeDigestMismatch,
		},
		{
			name: "download failure is redacted",
			mutate: func(fixture *artifactFixture) {
				fixture.repository.fetchErrDigest = fixture.descriptors[MediaTypeSBOM].Digest.String()
			},
			wantCode: CodeDownloadFailed,
		},
		{
			name: "nil component stream",
			mutate: func(fixture *artifactFixture) {
				fixture.repository.fetchNilDigest = fixture.descriptors[MediaTypeSBOM].Digest.String()
			},
			wantCode: CodeDownloadFailed,
		},
		{
			name: "unclean close",
			mutate: func(fixture *artifactFixture) {
				fixture.repository.closeErrDigest = fixture.descriptors[MediaTypeProvenance].Digest.String()
			},
			wantCode: CodeDownloadFailed,
		},
		{
			name: "required verifier rejects",
			verifier: VerificationFunc(func(context.Context, Entry) error {
				return errors.New("verifier-private-sentinel")
			}),
			wantCode: CodeVerificationFailed,
		},
		{
			name: "verified descriptor contains invalid zstd",
			mutate: func(fixture *artifactFixture) {
				data := []byte("not-a-zstd-frame")
				descriptor := descriptorFor(MediaTypeQCOW2Zstd, data)
				descriptor.Annotations = map[string]string{ociTitleAnnotation: "image.qcow2.zst"}
				fixture.repository.blobs[descriptor.Digest.String()] = data
				fixture.descriptors[MediaTypeQCOW2Zstd] = descriptor
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Layers[0] = descriptor
				})
			},
			wantCode: CodeExtractionFailed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newArtifactFixture(t)
			if test.mutate != nil {
				test.mutate(&fixture)
			}
			verifier := test.verifier
			if verifier == nil {
				verifier = acceptingVerifier(t, fixture.image)
			}
			puller, cache := newTestPuller(t, fixture, verifier, nil)
			_, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
			assertImageErrorCode(t, err, test.wantCode)
			if strings.Contains(err.Error(), "private-sentinel") {
				t.Fatalf("wrapped cause escaped redacted error: %v", err)
			}
			if _, statErr := os.Lstat(digestPath(cache.root, fixture.repository.manifest.Digest.String())); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed pull became runnable: %v", statErr)
			}
			partials, globErr := filepath.Glob(filepath.Join(cache.root, "sha256", ".partial-*"))
			if globErr != nil || len(partials) != 0 {
				t.Fatalf("partial data remained: %v err=%v", partials, globErr)
			}
		})
	}
}

func TestCompressedDigestMismatchBlocksBeforeDecoder(t *testing.T) {
	fixture := newArtifactFixture(t)
	imageDescriptor := fixture.descriptors[MediaTypeQCOW2Zstd]
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	fixture.repository.blobs[imageDescriptor.Digest.String()] = encoder.EncodeAll([]byte("different valid image"), nil)
	encoder.Close()
	puller, cache := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), nil)
	decoderCalled := false
	puller.decompress = func(context.Context, io.Reader, io.Writer, int64) (int64, string, error) {
		decoderCalled = true
		return 0, "", errors.New("decoder must not run")
	}
	_, err = puller.Pull(context.Background(), "registry.example/repo/image:stable")
	assertImageErrorCode(t, err, CodeDigestMismatch)
	if decoderCalled {
		t.Fatal("descriptor-mismatched compressed bytes reached the decoder")
	}
	assertNoPartial(t, cache)
}

func TestCompressedStreamCloseFailureBlocksBeforeDecoder(t *testing.T) {
	fixture := newArtifactFixture(t)
	fixture.repository.closeErrDigest = fixture.descriptors[MediaTypeQCOW2Zstd].Digest.String()
	puller, cache := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), nil)
	decoderCalled := false
	puller.decompress = func(context.Context, io.Reader, io.Writer, int64) (int64, string, error) {
		decoderCalled = true
		return 0, "", errors.New("decoder must not run")
	}
	_, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
	assertImageErrorCode(t, err, CodeDownloadFailed)
	if decoderCalled {
		t.Fatal("unclean compressed stream reached the decoder")
	}
	assertNoPartial(t, cache)
}

func TestPullRejectsTraversalDuplicateTypeAndBounds(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*artifactFixture)
		limits   func(*Limits)
		wantCode ErrorCode
	}{
		{
			name: "traversal title",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Layers[0].Annotations[ociTitleAnnotation] = "../image.qcow2.zst"
				})
			},
			wantCode: CodeManifestInvalid,
		},
		{
			name: "absolute title",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Layers[0].Annotations[ociTitleAnnotation] = "/image.qcow2.zst"
				})
			},
			wantCode: CodeManifestInvalid,
		},
		{
			name: "duplicate type",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Layers[1].MediaType = manifest.Layers[0].MediaType
				})
			},
			wantCode: CodeManifestInvalid,
		},
		{
			name: "unsupported type",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Layers[1].MediaType = "application/x-unknown"
				})
			},
			wantCode: CodeManifestInvalid,
		},
		{
			name: "compressed size bound",
			limits: func(limits *Limits) {
				limits.MaxCompressedImageBytes = 1
			},
			wantCode: CodeArtifactLimit,
		},
		{
			name: "uncompressed size bound",
			limits: func(limits *Limits) {
				limits.MaxUncompressedImageBytes = 4
			},
			wantCode: CodeArtifactLimit,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newArtifactFixture(t)
			if test.mutate != nil {
				test.mutate(&fixture)
			}
			puller, cache := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), test.limits)
			_, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
			assertImageErrorCode(t, err, test.wantCode)
			if _, statErr := os.Lstat(digestPath(cache.root, fixture.repository.manifest.Digest.String())); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("invalid artifact became runnable: %v", statErr)
			}
		})
	}
}

func TestPullRejectsNoncanonicalOCIFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*artifactFixture)
	}{
		{
			name: "manifest artifact type",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.ArtifactType = "application/vnd.private-vm.unsupported"
				})
			},
		},
		{
			name: "manifest subject",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					subject := fixture.descriptors[MediaTypeManifest]
					manifest.Subject = &subject
				})
			},
		},
		{
			name: "manifest annotation",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Annotations = map[string]string{"org.example.unsupported": "value"}
				})
			},
		},
		{
			name: "config URL",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Config.URLs = []string{"https://redirect.invalid/config"}
				})
			},
		},
		{
			name: "config embedded data",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Config.Data = []byte(canonicalEmptyConfig)
				})
			},
		},
		{
			name: "config annotation",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Config.Annotations = map[string]string{"org.example.unsupported": "value"}
				})
			},
		},
		{
			name: "config platform",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Config.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
				})
			},
		},
		{
			name: "config artifact type",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Config.ArtifactType = "application/vnd.private-vm.unsupported"
				})
			},
		},
		{
			name: "layer URL",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Layers[0].URLs = []string{"https://redirect.invalid/layer"}
				})
			},
		},
		{
			name: "layer embedded data",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Layers[0].Data = []byte("embedded")
				})
			},
		},
		{
			name: "layer platform",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Layers[0].Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
				})
			},
		},
		{
			name: "layer artifact type",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Layers[0].ArtifactType = "application/vnd.private-vm.unsupported"
				})
			},
		},
		{
			name: "layer extra annotation",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Layers[0].Annotations["org.example.unsupported"] = "value"
				})
			},
		},
		{
			name: "layer missing title",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Layers[0].Annotations = nil
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newArtifactFixture(t)
			test.mutate(&fixture)
			puller, cache := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), nil)
			_, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
			assertImageErrorCode(t, err, CodeManifestInvalid)
			assertNoPartial(t, cache)
		})
	}
}

func TestPullRequiresExactCanonicalEmptyConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*artifactFixture)
		code   ErrorCode
	}{
		{
			name: "media type",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Config.MediaType = "application/json"
				})
			},
			code: CodeManifestInvalid,
		},
		{
			name: "size",
			mutate: func(fixture *artifactFixture) {
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Config.Size++
				})
			},
			code: CodeManifestInvalid,
		},
		{
			name: "digest",
			mutate: func(fixture *artifactFixture) {
				data := []byte("[]")
				descriptor := descriptorFor(emptyConfigMediaType, data)
				fixture.repository.blobs[descriptor.Digest.String()] = data
				mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
					manifest.Config = descriptor
				})
			},
			code: CodeManifestInvalid,
		},
		{
			name: "fetched bytes",
			mutate: func(fixture *artifactFixture) {
				canonicalDigest := digest.FromString(canonicalEmptyConfig).String()
				fixture.repository.blobs[canonicalDigest] = []byte("[]")
			},
			code: CodeDigestMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newArtifactFixture(t)
			test.mutate(&fixture)
			puller, cache := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), nil)
			_, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
			assertImageErrorCode(t, err, test.code)
			assertNoPartial(t, cache)
		})
	}
}

func TestPullRejectsAlternateResolvedManifestDescriptorChannels(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ocispec.Descriptor)
	}{
		{name: "URL", mutate: func(descriptor *ocispec.Descriptor) { descriptor.URLs = []string{"https://redirect.invalid/manifest"} }},
		{name: "embedded data", mutate: func(descriptor *ocispec.Descriptor) { descriptor.Data = []byte("embedded") }},
		{name: "annotation", mutate: func(descriptor *ocispec.Descriptor) {
			descriptor.Annotations = map[string]string{"org.example.unsupported": "value"}
		}},
		{name: "platform", mutate: func(descriptor *ocispec.Descriptor) {
			descriptor.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
		}},
		{name: "artifact type", mutate: func(descriptor *ocispec.Descriptor) {
			descriptor.ArtifactType = "application/vnd.private-vm.unsupported"
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newArtifactFixture(t)
			test.mutate(&fixture.repository.manifest)
			puller, cache := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), nil)
			_, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
			assertImageErrorCode(t, err, CodeManifestInvalid)
			if calls := fixture.repository.callLog(); len(calls) != 1 {
				t.Fatalf("noncanonical resolved descriptor reached fetch: %v", calls)
			}
			assertNoPartial(t, cache)
		})
	}
}

func TestPullCancellationAndTimeoutCleanUp(t *testing.T) {
	t.Run("cancelled fetch", func(t *testing.T) {
		fixture := newArtifactFixture(t)
		fixture.repository.fetchWaitDigest = fixture.descriptors[MediaTypeManifest].Digest.String()
		fixture.repository.fetchStarted = make(chan struct{})
		puller, cache := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), nil)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := puller.Pull(ctx, "registry.example/repo/image:stable")
			result <- err
		}()
		select {
		case <-fixture.repository.fetchStarted:
		case <-time.After(time.Second):
			t.Fatal("pull did not reach the cancellable layer fetch")
		}
		cancel()
		var err error
		select {
		case err = <-result:
		case <-time.After(time.Second):
			t.Fatal("cancelled pull did not return")
		}
		assertImageErrorCode(t, err, CodePullCancelled)
		assertNoPartial(t, cache)
	})

	t.Run("resolve timeout", func(t *testing.T) {
		fixture := newArtifactFixture(t)
		fixture.repository.resolveWait = true
		puller, cache := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), nil)
		_, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
		assertImageErrorCode(t, err, CodePullTimeout)
		assertNoPartial(t, cache)
	})
}

func TestPullRejectsTamperedCachedFile(t *testing.T) {
	fixture := newArtifactFixture(t)
	puller, _ := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), nil)
	entry, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(entry.ImagePath, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = puller.Pull(context.Background(), "registry.example/repo/image:stable")
	assertImageErrorCode(t, err, CodeCacheInvalid)
}

func TestPullRejectsCachedDigestAndTypeTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, entry Entry)
		code   ErrorCode
	}{
		{
			name: "content digest",
			mutate: func(t *testing.T, entry Entry) {
				t.Helper()
				if err := os.Chmod(entry.ManifestPath, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(entry.ManifestPath, []byte("tampered"), 0o444); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(entry.ManifestPath, 0o444); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeDigestMismatch,
		},
		{
			name: "symbolic link type",
			mutate: func(t *testing.T, entry Entry) {
				t.Helper()
				if err := os.Chmod(entry.Directory, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(entry.ManifestPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(entry.ImagePath, entry.ManifestPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(entry.Directory, 0o555); err != nil {
					t.Fatal(err)
				}
			},
			code: CodeCacheInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newArtifactFixture(t)
			puller, _ := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), nil)
			entry, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(t, entry)
			_, err = puller.Pull(context.Background(), "registry.example/repo/image:stable")
			assertImageErrorCode(t, err, test.code)
		})
	}
}

func TestPullDigestReferenceMustResolveExactly(t *testing.T) {
	fixture := newArtifactFixture(t)
	puller, _ := newTestPuller(t, fixture, acceptingVerifier(t, fixture.image), nil)
	wrong := "sha256:" + strings.Repeat("a", 64)
	_, err := puller.Pull(context.Background(), "registry.example/repo/image@"+wrong)
	assertImageErrorCode(t, err, CodeDigestMismatch)
	if calls := fixture.repository.callLog(); !reflect.DeepEqual(calls, []string{"resolve:" + wrong}) {
		t.Fatalf("digest mismatch fetched content: %v", calls)
	}
}

func TestPullConcurrentPublicationConvergesOnOneDigestEntry(t *testing.T) {
	fixture := newArtifactFixture(t)
	verifyCount := 0
	var verifyMu sync.Mutex
	verifier := VerificationFunc(func(context.Context, Entry) error {
		verifyMu.Lock()
		verifyCount++
		verifyMu.Unlock()
		return nil
	})
	puller, cache := newTestPuller(t, fixture, verifier, nil)
	start := make(chan struct{})
	results := make(chan struct {
		entry Entry
		err   error
	}, 2)
	for range 2 {
		go func() {
			<-start
			entry, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
			results <- struct {
				entry Entry
				err   error
			}{entry: entry, err: err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent pulls failed: first=%v second=%v", first.err, second.err)
	}
	if first.entry.Directory != second.entry.Directory || first.entry.ManifestDigest != second.entry.ManifestDigest {
		t.Fatalf("concurrent pulls diverged: first=%#v second=%#v", first.entry, second.entry)
	}
	assertNoPartial(t, cache)
	verifyMu.Lock()
	defer verifyMu.Unlock()
	if verifyCount < 2 {
		t.Fatalf("a concurrent result bypassed verification: count=%d", verifyCount)
	}
}

func TestNewCacheRejectsSymlinkRoot(t *testing.T) {
	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(parent, "cache")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatal(err)
	}
	_, err := NewCache(linkRoot, os.Geteuid())
	assertImageErrorCode(t, err, CodeCacheInvalid)
}

func TestNewPullerRequiresTrustVerifier(t *testing.T) {
	fixture := newArtifactFixture(t)
	cache, err := NewCache(t.TempDir(), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	registerCacheCleanup(t, cache)
	_, err = NewPuller(&fakeRepositoryFactory{repository: fixture.repository}, cache, nil, DefaultLimits())
	assertImageErrorCode(t, err, CodeVerificationMissing)
	var nilVerifier VerificationFunc
	_, err = NewPuller(&fakeRepositoryFactory{repository: fixture.repository}, cache, nilVerifier, DefaultLimits())
	assertImageErrorCode(t, err, CodeVerificationMissing)
	var nilFactory *fakeRepositoryFactory
	_, err = NewPuller(nilFactory, cache, acceptingVerifier(t, fixture.image), DefaultLimits())
	assertImageErrorCode(t, err, CodeCacheInvalid)
}

func TestPullRejectsTypedNilRepository(t *testing.T) {
	fixture := newArtifactFixture(t)
	cache, err := NewCache(t.TempDir(), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	registerCacheCleanup(t, cache)
	var nilRepository *fakeRepository
	puller, err := NewPuller(&fakeRepositoryFactory{repository: nilRepository}, cache, acceptingVerifier(t, fixture.image), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	_, err = puller.Pull(context.Background(), "registry.example/repo/image:stable")
	assertImageErrorCode(t, err, CodeResolveFailed)
}

func TestORASFactoryUsesAnonymousBoundedHTTPSClient(t *testing.T) {
	supplied := &http.Client{}
	repository, err := (ORASFactory{HTTPClient: supplied}).Open("ghcr.io/stevenbuglione/private-vm/workstation-basic")
	if err != nil {
		t.Fatal(err)
	}
	remoteRepository, ok := repository.(*remote.Repository)
	if !ok {
		t.Fatalf("unexpected repository implementation %T", repository)
	}
	if remoteRepository.PlainHTTP {
		t.Fatal("public repository unexpectedly permits plaintext HTTP")
	}
	authClient, ok := remoteRepository.Client.(*auth.Client)
	if !ok || authClient.Client == nil || authClient.Client.Timeout != defaultHTTPRequestTimeout {
		t.Fatalf("ORAS client is not bounded: %#v", remoteRepository.Client)
	}
	if authClient.Credential != nil {
		t.Fatal("anonymous client unexpectedly configured a credential callback")
	}
	if supplied.Timeout != 0 {
		t.Fatal("factory mutated the caller-owned HTTP client")
	}
}

// TestORASAnonymousResolve is an opt-in acceptance check for a published public
// artifact. It deliberately resolves only; the normal Pull path fetches by the
// resulting immutable descriptor and requires IMG-002/003 verification.
func TestORASAnonymousResolve(t *testing.T) {
	reference := os.Getenv("PRIVATE_VM_TEST_PUBLIC_OCI_REFERENCE")
	if reference == "" {
		t.Skip("set PRIVATE_VM_TEST_PUBLIC_OCI_REFERENCE to a public tag or digest")
	}
	parsed, err := parsePullReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := (ORASFactory{}).Open(parsed.Registry + "/" + parsed.Repository)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	descriptor, err := repository.Resolve(ctx, parsed.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Size < 1 || descriptor.Size > DefaultLimits().MaxManifestBytes || !validSHA256Digest(descriptor.Digest) {
		t.Fatalf("anonymous resolution returned an unsafe descriptor: %#v", descriptor)
	}
}

func FuzzOCIManifest(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		_, _ = decodeOCIManifest(data, DefaultLimits())
	})
}

func mutateManifest(t *testing.T, fixture *artifactFixture, mutate func(*ocispec.Manifest)) {
	t.Helper()
	data := fixture.repository.blobs[fixture.repository.manifest.Digest.String()]
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	mutate(&manifest)
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	delete(fixture.repository.blobs, fixture.repository.manifest.Digest.String())
	fixture.repository.manifest = descriptorFor(ocispec.MediaTypeImageManifest, data)
	fixture.repository.blobs[fixture.repository.manifest.Digest.String()] = data
}

func assertImageErrorCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var imageErr *Error
	if !errors.As(err, &imageErr) {
		t.Fatalf("expected image error %s, got %T %v", want, err, err)
	}
	if imageErr.Code() != want {
		t.Fatalf("error code=%s want=%s err=%v", imageErr.Code(), want, err)
	}
	if imageErr.Message() == "" || imageErr.Remediation() == "" {
		t.Fatalf("error lacks safe message/remediation: %#v", imageErr)
	}
}

func assertNoPartial(t *testing.T, cache *Cache) {
	t.Helper()
	partials, err := filepath.Glob(filepath.Join(cache.root, "sha256", ".partial-*"))
	if err != nil || len(partials) != 0 {
		t.Fatalf("partial cache remains: %v err=%v", partials, err)
	}
}

func infoMode(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode()
}

func registerCacheCleanup(t *testing.T, cache *Cache) {
	t.Helper()
	t.Cleanup(func() {
		entries, _ := os.ReadDir(filepath.Join(cache.root, "sha256"))
		for _, entry := range entries {
			_ = os.Chmod(filepath.Join(cache.root, "sha256", entry.Name()), 0o700)
		}
	})
}
