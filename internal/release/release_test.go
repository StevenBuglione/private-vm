package release

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

type fakeSource struct {
	dirty bool
	block bool
}

func (source fakeSource) Run(ctx context.Context, arguments ...string) ([]byte, error) {
	if source.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	command := strings.Join(arguments, " ")
	switch command {
	case "rev-parse HEAD", "rev-list -n 1 v1.2.3":
		return []byte(testCommit + "\n"), nil
	case "remote get-url origin":
		return []byte("https://github.com/StevenBuglione/private-vm\n"), nil
	case "status --porcelain=v1 --untracked-files=all":
		if source.dirty {
			return []byte(" M private\n"), nil
		}
		return nil, nil
	case "merge-base --is-ancestor " + testCommit + " refs/remotes/origin/main":
		return nil, nil
	case "show -s --format=%ct " + testCommit:
		return []byte("1700000000\n"), nil
	default:
		return nil, errors.New("unexpected git command")
	}
}

type fakeImages struct{ err error }

func (images fakeImages) Verify(ctx context.Context, _, role, bundle string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if images.err != nil {
		return "", images.err
	}
	seed := role + bundle
	character := "a"
	if seed != "" {
		character = string("abcdef"[len(seed)%6])
	}
	return "sha256:" + strings.Repeat(character, 64), nil
}

func prepareFixture(t *testing.T, runner sourceRunner, images imageVerifier) (PrepareResult, PrepareOptions) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("1.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 3)
	for index := range paths {
		paths[index] = filepath.Join(root, []string{"input.deb", "input.rpm", "input.tar.zst"}[index])
		if err := os.WriteFile(paths[index], []byte("public-package-"+string(rune('a'+index))), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	options := PrepareOptions{
		WorkDir: root, OutputDir: filepath.Join(root, "prepared"), DEBPath: paths[0], RPMPath: paths[1], GenericPath: paths[2],
		ReleaseTag: "v1.2.3", SourceCommit: testCommit, SourceRef: "refs/tags/v1.2.3",
		RepositoryID: OfficialRepositoryID, OwnerID: OfficialOwnerID, RunID: "123", RunAttempt: "1", Timeout: time.Second,
	}
	result, err := prepare(context.Background(), options, runner, images)
	if err != nil {
		t.Fatal(err)
	}
	return result, options
}

func TestPrepareSuccessAndFailureCleanup(t *testing.T) {
	result, _ := prepareFixture(t, fakeSource{}, fakeImages{})
	if len(result.Index.Packages) != 3 || len(result.Index.Images) != 6 {
		t.Fatal("incomplete release index")
	}
	if _, err := os.Stat(filepath.Join(result.Directory, "release-index.json")); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		source fakeSource
		images fakeImages
		code   string
	}{
		{"dirty", fakeSource{dirty: true}, fakeImages{}, CodeSourceUnprotected},
		{"image-failure", fakeSource{}, fakeImages{err: errors.New("private remote detail")}, CodeVerifyFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("1.2.3\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			paths := []string{filepath.Join(root, "a.deb"), filepath.Join(root, "b.rpm"), filepath.Join(root, "c.tar.zst")}
			for _, path := range paths {
				if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(root, "prepared")
			_, err := prepare(context.Background(), PrepareOptions{WorkDir: root, OutputDir: output, DEBPath: paths[0], RPMPath: paths[1], GenericPath: paths[2], ReleaseTag: "v1.2.3", SourceCommit: testCommit, SourceRef: "refs/tags/v1.2.3", RepositoryID: OfficialRepositoryID, OwnerID: OfficialOwnerID, RunID: "1", RunAttempt: "1", Timeout: time.Second}, test.source, test.images)
			var safe *Error
			if !errors.As(err, &safe) || safe.Code != test.code || strings.Contains(err.Error(), "private remote detail") {
				t.Fatalf("unexpected redacted error: %v", err)
			}
			if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("partial output remained: %v", statErr)
			}
		})
	}
}

func TestPrepareCancellationAndTimeout(t *testing.T) {
	for _, test := range []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		code    string
	}{
		{"cancel", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, CodeCancelled},
		{"timeout", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), time.Millisecond)
		}, CodeTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.context()
			defer cancel()
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("1.2.3\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			paths := []string{filepath.Join(root, "a.deb"), filepath.Join(root, "b.rpm"), filepath.Join(root, "c.tar.zst")}
			for _, path := range paths {
				if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := prepare(ctx, PrepareOptions{WorkDir: root, OutputDir: filepath.Join(root, "out"), DEBPath: paths[0], RPMPath: paths[1], GenericPath: paths[2], ReleaseTag: "v1.2.3", SourceCommit: testCommit, SourceRef: "refs/tags/v1.2.3", RepositoryID: OfficialRepositoryID, OwnerID: OfficialOwnerID, RunID: "1", RunAttempt: "1", Timeout: time.Millisecond}, fakeSource{block: true}, fakeImages{})
			var safe *Error
			if !errors.As(err, &safe) || safe.Code != test.code {
				t.Fatalf("got %v", err)
			}
		})
	}
}

type fakeProvenance struct{ err error }

func (verifier fakeProvenance) Verify(context.Context, []byte, PackageManifest) error {
	return verifier.err
}

type fakePublisher struct {
	mu        sync.Mutex
	uploads   int
	failAt    int
	deleted   bool
	published bool
	block     bool
	deleteErr error
}

type fakeAcceptance struct {
	failAt       int
	calls        int
	environments [][]string
}

type fakeFetcher struct {
	assets map[string][]byte
	err    error
	block  bool
}

func (fetcher fakeFetcher) Fetch(ctx context.Context, _ string) (map[string][]byte, error) {
	if fetcher.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if fetcher.err != nil {
		return nil, fetcher.err
	}
	return fetcher.assets, nil
}

func (runner *fakeAcceptance) Run(ctx context.Context, _ string, _ []string, environment []string) error {
	runner.calls++
	runner.environments = append(runner.environments, append([]string(nil), environment...))
	if err := ctx.Err(); err != nil {
		return err
	}
	if runner.failAt == runner.calls {
		return errors.New("private command output")
	}
	return nil
}

func (publisher *fakePublisher) CreateDraft(ctx context.Context, _, _ string) (int64, string, error) {
	if publisher.block {
		<-ctx.Done()
		return 0, "", ctx.Err()
	}
	return 7, "fixed", nil
}
func (publisher *fakePublisher) Upload(_ context.Context, _ int64, _ string, _ releaseAsset) error {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	publisher.uploads++
	if publisher.failAt == publisher.uploads {
		return errors.New("upload detail")
	}
	return nil
}
func (publisher *fakePublisher) Publish(context.Context, int64) error {
	publisher.published = true
	return nil
}
func (publisher *fakePublisher) DeleteDraft(context.Context, int64) error {
	publisher.deleted = true
	return publisher.deleteErr
}

func publishFixture(t *testing.T, publisher *fakePublisher) error {
	t.Helper()
	result, options := prepareFixture(t, fakeSource{}, fakeImages{})
	provenance := map[ArtifactKind]string{}
	for _, kind := range artifactKinds {
		path := filepath.Join(filepath.Dir(result.Directory), string(kind)+".bundle")
		if err := os.WriteFile(path, []byte("public-attestation"), 0o600); err != nil {
			t.Fatal(err)
		}
		provenance[kind] = path
	}
	token, err := secret.New([]byte("public-test-token"))
	if err != nil {
		t.Fatal(err)
	}
	defer token.Destroy()
	returnErr := func() error {
		_, err := publish(context.Background(), PublishOptions{Directory: result.Directory, ReleaseTag: options.ReleaseTag, SourceCommit: options.SourceCommit, Provenance: provenance, Token: token, Timeout: time.Second}, publisher, fakeProvenance{})
		return err
	}()
	if _, statErr := os.Stat(result.Directory); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("staging remained: %v", statErr)
	}
	return returnErr
}

func TestPublishSuccessFailureRollbackAndCleanup(t *testing.T) {
	success := &fakePublisher{}
	if err := publishFixture(t, success); err != nil {
		t.Fatal(err)
	}
	if !success.published || success.deleted || success.uploads != 13 {
		t.Fatalf("unexpected publisher: %+v", success)
	}
	failure := &fakePublisher{failAt: 3}
	err := publishFixture(t, failure)
	var safe *Error
	if !errors.As(err, &safe) || safe.Code != CodePublishFailed || !failure.deleted || strings.Contains(err.Error(), "upload detail") {
		t.Fatalf("unexpected rollback: %v %+v", err, failure)
	}
	cleanupFailure := &fakePublisher{failAt: 1, deleteErr: errors.New("delete detail")}
	err = publishFixture(t, cleanupFailure)
	if !errors.As(err, &safe) || safe.Code != CodeCleanupIncomplete || strings.Contains(err.Error(), "delete detail") {
		t.Fatalf("unexpected cleanup error: %v", err)
	}
}

func TestPublishCancellationAndTimeout(t *testing.T) {
	for _, code := range []string{CodeTimeout, CodeCancelled} {
		t.Run(code, func(t *testing.T) {
			publisher := &fakePublisher{block: true}
			if code == CodeCancelled {
				// A pre-cancelled context is exercised through a blocking source in prepare;
				// publication cancellation uses the same stable context mapper.
				if got := contextReleaseError(func() context.Context { c, x := context.WithCancel(context.Background()); x(); return c }(), context.Canceled); !strings.Contains(got.Error(), CodeCancelled) {
					t.Fatal(got)
				}
				return
			}
			result, options := prepareFixture(t, fakeSource{}, fakeImages{})
			provenance := map[ArtifactKind]string{}
			for _, kind := range artifactKinds {
				path := filepath.Join(filepath.Dir(result.Directory), string(kind)+".bundle")
				_ = os.WriteFile(path, []byte("bundle"), 0o600)
				provenance[kind] = path
			}
			token, _ := secret.New([]byte("token"))
			defer token.Destroy()
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()
			_, err := publish(ctx, PublishOptions{Directory: result.Directory, ReleaseTag: options.ReleaseTag, SourceCommit: options.SourceCommit, Provenance: provenance, Token: token, Timeout: time.Second}, publisher, fakeProvenance{})
			var safe *Error
			if !errors.As(err, &safe) || safe.Code != CodeTimeout {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestSourceAcceptanceEvidenceAndFailFast(t *testing.T) {
	for _, test := range []struct {
		name              string
		failAt, wantCalls int
	}{{"source-pass-live-blocked", 0, len(sourceAcceptanceCommands)}, {"first-failure-stops", 2, 2}} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			jsonPath := filepath.Join(root, "evidence.json")
			junitPath := filepath.Join(root, "evidence.xml")
			runner := &fakeAcceptance{failAt: test.failAt}
			err := runSourceAcceptance(context.Background(), root, jsonPath, junitPath, runner)
			var safe *Error
			if !errors.As(err, &safe) || safe.Code != CodeGatesIncomplete || runner.calls != test.wantCalls || strings.Contains(err.Error(), "private command output") {
				t.Fatalf("unexpected result: %v calls=%d", err, runner.calls)
			}
			jsonBytes, readErr := os.ReadFile(jsonPath)
			if readErr != nil || !strings.Contains(string(jsonBytes), `"status":"blocked"`) || strings.Contains(string(jsonBytes), "private command output") {
				t.Fatalf("unsafe JSON evidence: %s %v", jsonBytes, readErr)
			}
			junitBytes, readErr := os.ReadFile(junitPath)
			if readErr != nil || !strings.Contains(string(junitBytes), "LIVE_GATE_UNAVAILABLE") {
				t.Fatalf("invalid JUnit: %s %v", junitBytes, readErr)
			}
			environment := strings.Join(runner.environments[0], "\n")
			for _, required := range []string{"GOMAXPROCS=2", "GOMEMLIMIT=2500MiB", "max-jobs = 1", "cores = 2"} {
				if !strings.Contains(environment, required) {
					t.Fatalf("missing limit %q", required)
				}
			}
		})
	}
}

func TestAnonymousVerifySuccessFailureAndCancellation(t *testing.T) {
	result, options := prepareFixture(t, fakeSource{}, fakeImages{})
	assets := map[string][]byte{}
	for _, artifact := range result.Index.Packages {
		if err := os.WriteFile(filepath.Join(result.Directory, artifact.Provenance), []byte("public-attestation"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{artifact.File, artifact.Manifest, artifact.SBOM, artifact.Provenance} {
			data, err := os.ReadFile(filepath.Join(result.Directory, name))
			if err != nil {
				t.Fatal(err)
			}
			assets[name] = data
		}
	}
	indexBytes, err := os.ReadFile(filepath.Join(result.Directory, "release-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	assets["release-index.json"] = indexBytes
	verified, err := verify(context.Background(), VerifyOptions{ReleaseTag: options.ReleaseTag, SourceCommit: options.SourceCommit, Timeout: time.Second}, fakeFetcher{assets: assets}, fakeProvenance{}, fakeImages{})
	if err != nil || !verified.Verified || verified.PackageCount != 3 || verified.ImageCount != 6 {
		t.Fatalf("unexpected verification: %+v %v", verified, err)
	}
	_, err = verify(context.Background(), VerifyOptions{ReleaseTag: options.ReleaseTag, SourceCommit: options.SourceCommit, Timeout: time.Second}, fakeFetcher{assets: map[string][]byte{"release-index.json": indexBytes}}, fakeProvenance{}, fakeImages{})
	var safe *Error
	if !errors.As(err, &safe) || safe.Code != CodeVerifyFailed {
		t.Fatalf("unexpected incomplete error: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err = verify(ctx, VerifyOptions{ReleaseTag: options.ReleaseTag, SourceCommit: options.SourceCommit, Timeout: time.Second}, fakeFetcher{block: true}, fakeProvenance{}, fakeImages{})
	if !errors.As(err, &safe) || safe.Code != CodeTimeout {
		t.Fatalf("unexpected timeout: %v", err)
	}
}
