package image

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
)

const releaseTestCommit = "0123456789abcdef0123456789abcdef01234567"

type releaseFakeRunner struct {
	options       PrepareOptions
	nixError      error
	waitNix       bool
	ancestryError error
}

func (runner *releaseFakeRunner) Run(ctx context.Context, _ string, name string, arguments ...string) ([]byte, error) {
	if name == "git" {
		switch arguments[0] {
		case "rev-parse", "rev-list":
			return []byte(runner.options.SourceCommit + "\n"), nil
		case "remote":
			return []byte("https://github.com/" + officialRepository + "\n"), nil
		case "status":
			return nil, nil
		case "merge-base":
			return nil, runner.ancestryError
		case "show":
			return []byte("1700000000\n"), nil
		}
	}
	if name == "nix" && runner.waitNix {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if name == "nix" {
		return nil, runner.nixError
	}
	return nil, errors.New("unexpected command")
}

func validPrepareOptions(t *testing.T) PrepareOptions {
	t.Helper()
	work := t.TempDir()
	return PrepareOptions{
		WorkDir: work, OutputDir: filepath.Join(work, "prepared"),
		ImageTarget: "image-scanner", ClosureTarget: "closure-scanner",
		ReleaseTag: "v1.2.3-rc.1", Role: "scanner",
		Repository:       "ghcr.io/stevenbuglione/private-vm/scanner",
		SourceRepository: officialRepository, SourceCommit: releaseTestCommit,
		SourceRef: "refs/tags/v1.2.3-rc.1", Workflow: officialWorkflow,
		RepositoryID: officialRepositoryID, OwnerID: officialRepositoryOwnerID,
		RunID: "1234", RunAttempt: "1",
	}
}

func TestPrepareReleaseFailureCancellationTimeoutAndCleanup(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(context.Context, context.CancelFunc, *releaseFakeRunner)
		wantCode  ErrorCode
	}{
		{name: "failure", configure: func(_ context.Context, _ context.CancelFunc, runner *releaseFakeRunner) {
			runner.nixError = errors.New("private build failure")
		}, wantCode: CodeReleaseBuildFailed},
		{name: "unmerged-tag", configure: func(_ context.Context, _ context.CancelFunc, runner *releaseFakeRunner) {
			runner.ancestryError = errors.New("not an ancestor")
		}, wantCode: CodeReleaseInvalid},
		{name: "cancellation", configure: func(_ context.Context, cancel context.CancelFunc, runner *releaseFakeRunner) {
			runner.waitNix = true
			time.AfterFunc(time.Millisecond, cancel)
		}, wantCode: CodePullCancelled},
		{name: "timeout", configure: func(_ context.Context, _ context.CancelFunc, runner *releaseFakeRunner) {
			runner.waitNix = true
		}, wantCode: CodePullTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := validPrepareOptions(t)
			base := context.Background()
			var ctx context.Context
			var cancel context.CancelFunc
			if test.name == "timeout" {
				ctx, cancel = context.WithTimeout(base, time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(base)
			}
			defer cancel()
			runner := &releaseFakeRunner{options: options}
			test.configure(ctx, cancel, runner)
			_, err := prepareRelease(ctx, options, runner)
			assertImageErrorCode(t, err, test.wantCode)
			if _, statErr := os.Lstat(options.OutputDir); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("partial release directory remained: %v", statErr)
			}
		})
	}
}

func TestSelectAndValidateReleaseQCOW2(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "image.qcow2")
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	writeQCOW2Fixture(t, path, 1<<20)
	selected, err := selectQCOW2Tree(root)
	if err != nil || selected != path {
		t.Fatalf("selected %q: %v", selected, err)
	}
	file, _, virtualSize, err := openValidatedQCOW2(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if virtualSize != 1<<20 {
		t.Fatalf("virtual size = %d", virtualSize)
	}

	if err := os.Symlink(path, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := selectQCOW2Tree(root); err == nil {
		t.Fatal("symlink in image tree was accepted")
	}
	if err := os.Remove(filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	writeQCOW2Fixture(t, filepath.Join(root, "second.qcow2"), 1<<20)
	if _, err := selectQCOW2Tree(root); err == nil {
		t.Fatal("ambiguous QCOW2 set was accepted")
	}
	header := make([]byte, 104)
	copy(header[:4], "QFI\xfb")
	binary.BigEndian.PutUint32(header[4:8], 2)
	bad := filepath.Join(t.TempDir(), "bad.qcow2")
	if err := os.WriteFile(bad, header, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := openValidatedQCOW2(bad); err == nil {
		t.Fatal("QCOW2 v2 was accepted")
	}
}

func TestQCOW2BackingEncryptionAndClosureFailuresAreRejected(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "backing", mutate: func(header []byte) { binary.BigEndian.PutUint64(header[8:16], 4096) }},
		{name: "encryption", mutate: func(header []byte) { binary.BigEndian.PutUint32(header[32:36], 1) }},
		{name: "cluster-bits", mutate: func(header []byte) { binary.BigEndian.PutUint32(header[20:24], 30) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "image.qcow2")
			writeQCOW2Fixture(t, path, 1<<20)
			header, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(header)
			if err := os.WriteFile(path, header, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := openValidatedQCOW2(path); err == nil {
				t.Fatal("unsafe QCOW2 header was accepted")
			}
		})
	}
	runner := &releaseFakeRunner{nixError: nil}
	if _, err := readNixClosure(context.Background(), runner, t.TempDir(), "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture"); err == nil {
		t.Fatal("empty Nix closure was accepted")
	}
}

func TestReleaseCompressionIsDeterministicAndBounded(t *testing.T) {
	input := bytes.Repeat([]byte("private-vm-qcow2-fixture"), 16_384)
	paths := []string{filepath.Join(t.TempDir(), "one.zst"), filepath.Join(t.TempDir(), "two.zst")}
	var digests []string
	for _, path := range paths {
		size, digest, err := compressReleaseImage(context.Background(), bytes.NewReader(input), path)
		if err != nil || size < 1 {
			t.Fatalf("compress: size=%d err=%v", size, err)
		}
		digests = append(digests, digest)
	}
	left, _ := os.ReadFile(paths[0])
	right, _ := os.ReadFile(paths[1])
	if digests[0] != digests[1] || !bytes.Equal(left, right) {
		t.Fatal("single-worker release compression was not deterministic")
	}
}

type fakePushFactory struct{ repository *fakePushRepository }

func (factory fakePushFactory) Open(string, string, string, *secret.Bytes) (pushRepository, error) {
	return factory.repository, nil
}

type fakePushRepository struct {
	mu         sync.Mutex
	tag        *ocispec.Descriptor
	pushes     []ocispec.Descriptor
	manifest   []byte
	tagWrites  int
	failPushAt int
	waitPush   bool
}

func (repository *fakePushRepository) Resolve(ctx context.Context, _ string) (ocispec.Descriptor, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.tag == nil {
		return ocispec.Descriptor{}, errdef.ErrNotFound
	}
	return *repository.tag, nil
}

func (repository *fakePushRepository) Push(ctx context.Context, descriptor ocispec.Descriptor, reader io.Reader) error {
	if repository.waitPush {
		<-ctx.Done()
		return ctx.Err()
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.pushes = append(repository.pushes, descriptor)
	if repository.failPushAt > 0 && len(repository.pushes) == repository.failPushAt {
		return errors.New("private partial push failure")
	}
	data, err := io.ReadAll(io.LimitReader(reader, descriptor.Size+1))
	if err != nil {
		return err
	}
	if int64(len(data)) != descriptor.Size || digestBytes(data) != descriptor.Digest.String() {
		return errors.New("descriptor mismatch")
	}
	if descriptor.MediaType == ocispec.MediaTypeImageManifest {
		repository.manifest = data
	}
	return nil
}

func (repository *fakePushRepository) PushReference(_ context.Context, descriptor ocispec.Descriptor, reader io.Reader, _ string) error {
	data, err := io.ReadAll(reader)
	if err != nil || digestBytes(data) != descriptor.Digest.String() {
		return errors.New("tag manifest mismatch")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.tagWrites++
	repository.tag = &descriptor
	return nil
}

func TestPublishReleaseSuccessDuplicatePartialCancellationTimeoutAndCleanup(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*fakePushRepository)
		context   func() (context.Context, context.CancelFunc)
		wantCode  ErrorCode
		success   bool
	}{
		{name: "success", success: true},
		{name: "duplicate", configure: func(repository *fakePushRepository) {
			descriptor := ocispec.Descriptor{Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
			repository.tag = &descriptor
		}, wantCode: CodeReleaseConflict},
		{name: "partial", configure: func(repository *fakePushRepository) { repository.failPushAt = 3 }, wantCode: CodeReleasePublishFailed},
		{name: "cancellation", configure: func(repository *fakePushRepository) { repository.waitPush = true }, context: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(time.Millisecond, cancel)
			return ctx, cancel
		}, wantCode: CodePullCancelled},
		{name: "timeout", configure: func(repository *fakePushRepository) { repository.waitPush = true }, context: func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), time.Millisecond)
		}, wantCode: CodePullTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, provenance := makePreparedPublication(t)
			repository := new(fakePushRepository)
			if test.configure != nil {
				test.configure(repository)
			}
			ctx, cancel := context.WithCancel(context.Background())
			if test.context != nil {
				cancel()
				ctx, cancel = test.context()
			}
			defer cancel()
			verifierCalled := false
			verifier := VerificationFunc(func(_ context.Context, entry Entry) error {
				verifierCalled = true
				if _, err := readCacheRecord(entry.RecordPath); err != nil {
					return err
				}
				return nil
			})
			result, err := publishRelease(ctx, options, fakePushFactory{repository}, verifier)
			if test.success {
				if err != nil || result.ManifestDigest == "" || repository.tagWrites != 1 || len(repository.pushes) != 6 {
					t.Fatalf("publish result=%+v err=%v pushes=%d tags=%d", result, err, len(repository.pushes), repository.tagWrites)
				}
				document, err := decodeOCIManifest(repository.manifest, DefaultLimits())
				if err != nil || len(document.Layers) != 4 {
					t.Fatalf("canonical OCI manifest: %v", err)
				}
			} else {
				assertImageErrorCode(t, err, test.wantCode)
				if repository.tagWrites != 0 {
					t.Fatal("failure published a tag")
				}
			}
			if !verifierCalled && test.name != "cancellation" && test.name != "timeout" {
				t.Fatal("local verifier was not called before publication")
			}
			if _, err := os.Lstat(options.Directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("release staging directory remained: %v", err)
			}
			if _, err := os.Stat(provenance); err != nil {
				t.Fatalf("actions bundle source was removed: %v", err)
			}
		})
	}
}

func TestEveryPartialPushFailureLeavesTagAbsent(t *testing.T) {
	for failurePoint := 1; failurePoint <= 6; failurePoint++ {
		t.Run(string(rune('0'+failurePoint)), func(t *testing.T) {
			options, _ := makePreparedPublication(t)
			repository := &fakePushRepository{failPushAt: failurePoint}
			_, err := publishRelease(context.Background(), options, fakePushFactory{repository}, VerificationFunc(func(context.Context, Entry) error { return nil }))
			assertImageErrorCode(t, err, CodeReleasePublishFailed)
			if repository.tagWrites != 0 || repository.tag != nil {
				t.Fatalf("failure point %d published a tag", failurePoint)
			}
		})
	}
}

func TestConditionalTagTransportAddsCreateOnlyPrecondition(t *testing.T) {
	base := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("If-None-Match") != "*" {
			t.Fatal("tag PUT lacked create-only precondition")
		}
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
	})
	transport := conditionalTagTransport{base: base, repository: "owner/repository", tag: "v1.2.3"}
	request, err := http.NewRequest(http.MethodPut, "https://ghcr.io/v2/owner/repository/manifests/v1.2.3", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestAnonymousVerificationResolvesThenPullsByDigest(t *testing.T) {
	fixture := newArtifactFixture(t)
	factory := &fakeRepositoryFactory{repository: fixture.repository}
	verified := false
	entry, err := verifyAnonymousRelease(context.Background(), AnonymousVerifyOptions{
		Repository: "ghcr.io/stevenbuglione/private-vm/scanner", ReleaseTag: "v1.2.3", Role: "scanner", Timeout: time.Minute,
	}, factory, VerificationFunc(func(context.Context, Entry) error { verified = true; return nil }))
	if err != nil {
		t.Fatal(err)
	}
	if !verified || entry.ManifestDigest != fixture.repository.manifest.Digest.String() || entry.Directory != "" {
		t.Fatalf("anonymous verification result=%+v verified=%v", entry, verified)
	}
	calls := fixture.repository.callLog()
	if len(calls) < 2 || calls[0] != "resolve:v1.2.3" || calls[1] != "resolve:"+fixture.repository.manifest.Digest.String() {
		t.Fatalf("anonymous operation order: %v", calls)
	}
}

func TestAnonymousReadOnlyCacheCleanup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "anonymous")
	entry := filepath.Join(root, "sha256", "digest")
	if err := os.MkdirAll(entry, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, "image.qcow2"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(entry, "image.qcow2"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(entry, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedReleaseTree(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("anonymous cache remained: %v", err)
	}
}

func makePreparedPublication(t *testing.T) (PublishOptions, string) {
	t.Helper()
	directory := t.TempDir()
	rawImage := qcow2FixtureBytes(1 << 20)
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	compressed := encoder.EncodeAll(rawImage, nil)
	encoder.Close()
	sbom := []byte("{\"spdxVersion\":\"SPDX-2.3\"}\n")
	bundle := "basic"
	manifest := Manifest{
		SchemaVersion: 1, Project: "private-vm", Role: "workstation", Bundle: &bundle,
		Architecture: "x86_64", SourceRepository: officialRepository, SourceCommit: releaseTestCommit,
		SourceRef: "refs/tags/v1.2.3", Workflow: officialWorkflow,
		ImageDigest: digestBytes(compressed), UncompressedSHA256: strings.TrimPrefix(digestBytes(rawImage), "sha256:"),
		CompressedSizeBytes: int64(len(compressed)), UncompressedSizeBytes: int64(len(rawImage)), VirtualSizeBytes: 1 << 20,
		NixOSVersion: frozenNixOSVersion, FlakeLockSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		GuestAPIMajor: 1, GuestAPIMinor: 0, MinimumQEMUVersion: frozenQEMUMinimum,
		Capabilities: append([]string(nil), roleCapabilities["workstation"]...), SBOMDigest: digestBytes(sbom), BuiltAt: "2026-01-01T00:00:00Z",
	}
	manifestBytes, err := encodeCanonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	receipt := ReleaseReceipt{
		SchemaVersion: 1, Project: "private-vm", ReleaseTag: "v1.2.3", Role: "workstation", Bundle: &bundle,
		Repository: "ghcr.io/stevenbuglione/private-vm/workstation-basic", SourceRepository: officialRepository,
		SourceCommit: releaseTestCommit, SourceRef: "refs/tags/v1.2.3", Workflow: officialWorkflow,
		ImageDigest: digestBytes(compressed), UncompressedSHA256: manifest.UncompressedSHA256,
		SBOMDigest: digestBytes(sbom), ManifestDigest: digestBytes(manifestBytes),
		CompressedSizeBytes: int64(len(compressed)), UncompressedSizeBytes: int64(len(rawImage)), VirtualSizeBytes: 1 << 20,
		Files: []string{"image.qcow2.zst", "manifest.json", "sbom.spdx.json", "predicate.json"},
	}
	receiptBytes, _ := encodeCanonicalJSON(receipt)
	for name, data := range map[string][]byte{
		"image.qcow2.zst": compressed, "manifest.json": manifestBytes,
		"sbom.spdx.json": sbom, "predicate.json": []byte("{}\n"), "release-receipt.json": receiptBytes,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	provenance := filepath.Join(t.TempDir(), "attestation.json")
	if err := os.WriteFile(provenance, []byte("{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := secret.New([]byte("test-token"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(token.Destroy)
	return PublishOptions{Directory: directory, ProvenancePath: provenance,
		Repository: receipt.Repository, ReleaseTag: receipt.ReleaseTag, Username: "github-actor", Token: token}, provenance
}

func writeQCOW2Fixture(t *testing.T, path string, virtualSize uint64) {
	t.Helper()
	header := qcow2FixtureBytes(virtualSize)
	if err := os.WriteFile(path, header, 0o600); err != nil {
		t.Fatal(err)
	}
}

func qcow2FixtureBytes(virtualSize uint64) []byte {
	header := make([]byte, 104)
	copy(header[:4], "QFI\xfb")
	binary.BigEndian.PutUint32(header[4:8], 3)
	binary.BigEndian.PutUint32(header[20:24], 16)
	binary.BigEndian.PutUint64(header[24:32], virtualSize)
	binary.BigEndian.PutUint32(header[96:100], 4)
	binary.BigEndian.PutUint32(header[100:104], 104)
	return header
}

func TestReleaseReceiptRejectsUnknownFields(t *testing.T) {
	options, _ := makePreparedPublication(t)
	path := filepath.Join(options.Directory, "release-receipt.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	value["registry_token"] = "must-not-be-accepted"
	data, _ = json.Marshal(value)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = loadPreparedPublication(context.Background(), options)
	assertImageErrorCode(t, err, CodeReleaseInvalid)
}
