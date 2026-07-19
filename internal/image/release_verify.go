package image

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// AnonymousVerifyOptions contains only public release identity. No credential
// callback, environment lookup, Docker store or authenticated fallback exists.
type AnonymousVerifyOptions struct {
	Repository string
	ReleaseTag string
	Role       string
	Bundle     string
	Timeout    time.Duration
}

// VerifyAnonymousRelease resolves the public tag once, then pulls and verifies
// exclusively by that immutable digest in a newly-created owner-only cache.
func VerifyAnonymousRelease(ctx context.Context, options AnonymousVerifyOptions) (Entry, error) {
	return verifyAnonymousRelease(ctx, options, ORASFactory{}, nil)
}

func verifyAnonymousRelease(ctx context.Context, options AnonymousVerifyOptions, factory RepositoryFactory, verifier Verifier) (result Entry, returnedErr error) {
	if options.Repository != "ghcr.io/stevenbuglione/private-vm/"+releaseImageName(options.Role, options.Bundle) ||
		!validRoleBundle(options.Role, options.Bundle) || !officialReleaseRefPattern.MatchString("refs/tags/"+options.ReleaseTag) {
		return Entry{}, releaseInvalid("The anonymous release reference does not match a frozen public image target.", nil)
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 30 * time.Minute
	}
	if timeout < time.Second || timeout > time.Hour {
		return Entry{}, releaseInvalid("The anonymous verification timeout is outside its finite bound.", nil)
	}
	verifyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	repository, err := factory.Open(options.Repository)
	if err != nil {
		return Entry{}, releasePublishFailed("The public OCI repository could not be opened anonymously.", err)
	}
	descriptor, err := repository.Resolve(verifyCtx, options.ReleaseTag)
	if err != nil {
		return Entry{}, contextError(verifyCtx, releasePublishFailed("The public release tag could not be resolved anonymously.", err))
	}
	limits := DefaultLimits()
	if err := validateManifestDescriptor(descriptor, limits); err != nil {
		return Entry{}, err
	}
	root, err := os.MkdirTemp("", "private-vm-anonymous-verify-")
	if err != nil {
		return Entry{}, releaseInvalid("The private anonymous-verification cache could not be created.", err)
	}
	defer func() {
		if cleanupErr := removeOwnedReleaseTree(root); cleanupErr != nil {
			result = Entry{}
			returnedErr = releaseInvalid("The anonymous-verification cache could not be removed completely.", errors.Join(returnedErr, cleanupErr))
		}
	}()
	if err := os.Chmod(root, 0o700); err != nil {
		return Entry{}, releaseInvalid("The anonymous-verification cache could not be secured.", err)
	}
	cache, err := NewCache(filepath.Clean(root), os.Geteuid())
	if err != nil {
		return Entry{}, err
	}
	policy := CompatibilityPolicy{
		Role: options.Role, Bundle: options.Bundle, HostArchitecture: runtime.GOARCH,
		GuestAPIMajor: 1, GuestAPIMinor: 0, MinimumGuestAPIMinor: 0,
		HostQEMUVersion: "10.2.4", NixOSVersion: frozenNixOSVersion, Limits: DefaultVerificationLimits(),
	}
	if verifier == nil {
		verifier, err = NewOfficialVerifier(policy)
		if err != nil {
			return Entry{}, err
		}
	}
	puller, err := NewPuller(factory, cache, verifier, limits)
	if err != nil {
		return Entry{}, err
	}
	entry, err := puller.Pull(verifyCtx, options.Repository+"@"+descriptor.Digest.String())
	if err != nil {
		return Entry{}, err
	}
	if entry.ManifestDigest != descriptor.Digest.String() {
		return Entry{}, imageError(CodeDigestMismatch, "Anonymous verification returned a different immutable digest.", "Do not use the package; inspect public GHCR state and the official release workflow.", nil)
	}
	// Entry files are intentionally deleted with the clean cache on return. Only
	// its immutable public identity is returned to the command for JSON evidence.
	entry.Directory = ""
	entry.ImagePath = ""
	entry.ManifestPath = ""
	entry.SBOMPath = ""
	entry.ProvenancePath = ""
	entry.RecordPath = ""
	return entry, nil
}

func removeOwnedReleaseTree(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return errors.New("invalid owner-controlled release tree root")
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) || fileUID(info) != os.Geteuid() {
			return errors.Join(err, errors.New("unsafe owner-controlled release tree entry"))
		}
		mode := os.FileMode(0o600)
		if info.IsDir() {
			mode = 0o700
		}
		return os.Chmod(path, mode)
	})
	if err != nil {
		return err
	}
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		return errors.New("owner-controlled release tree remained after cleanup")
	}
	return nil
}
