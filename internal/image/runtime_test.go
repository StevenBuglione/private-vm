package image

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSelectRuntimeImageReverifiesExactImmutableCacheEntry(t *testing.T) {
	fixture := newVerificationFixture(t)
	root := t.TempDir()
	cache, err := NewCache(root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	digestDirectory := filepath.Join(root, "sha256", fixture.record.OCIManifestDigest[len("sha256:"):])
	if err := os.Rename(fixture.entry.Directory, digestDirectory); err != nil {
		t.Fatal(err)
	}
	children, err := os.ReadDir(digestDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range children {
		if err := os.Chmod(filepath.Join(digestDirectory, child.Name()), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(digestDirectory, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(digestDirectory, 0o700)
		for _, child := range children {
			_ = os.Chmod(filepath.Join(digestDirectory, child.Name()), 0o600)
		}
	})

	verified := false
	image, err := cache.SelectRuntimeImage(context.Background(), RuntimeSelector{Role: "workstation", Bundle: "development"}, VerificationFunc(func(_ context.Context, entry Entry) error {
		verified = true
		if entry.ManifestDigest != fixture.record.OCIManifestDigest {
			t.Fatal("selector changed the immutable manifest digest")
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !verified || image.ManifestDigest != fixture.record.OCIManifestDigest || image.Entry.ImagePath != filepath.Join(digestDirectory, "image.qcow2") || image.SourceCommit != fixture.manifest.SourceCommit {
		t.Fatalf("runtime image = %+v, verified=%v", image, verified)
	}

	_, err = cache.SelectRuntimeImage(context.Background(), RuntimeSelector{Role: "workstation", Bundle: "basic"}, VerificationFunc(func(context.Context, Entry) error { return nil }))
	var classified *Error
	if !errors.As(err, &classified) || classified.Code() != CodeVerificationMissing {
		t.Fatalf("missing selector error = %v", err)
	}
}
