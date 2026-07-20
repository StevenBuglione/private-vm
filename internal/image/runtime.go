package image

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var cacheDigestDirectoryPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// RuntimeSelector is the exact role/bundle identity requested by the daemon.
// Non-workstation roles use an empty bundle.
type RuntimeSelector struct {
	Role   string
	Bundle string
}

// RuntimeImage is the bounded subset of an already verified cache entry needed
// to construct and authenticate a guest. It deliberately contains no mutable
// tag: ManifestDigest is the immutable OCI execution identity.
type RuntimeImage struct {
	Entry            Entry
	ManifestDigest   string
	ImageDigest      string
	SourceCommit     string
	Capabilities     []string
	VirtualSizeBytes uint64
}

// SelectRuntimeImage enumerates only immutable digest directories, validates
// each cache record, and requires exactly one image matching selector. The
// supplied verifier must apply the complete manifest/SBOM/provenance policy.
// Ambiguity fails closed instead of guessing between releases.
func (cache *Cache) SelectRuntimeImage(ctx context.Context, selector RuntimeSelector, verifier Verifier) (RuntimeImage, error) {
	if cache == nil || nilLike(verifier) || !validRoleBundle(selector.Role, selector.Bundle) {
		return RuntimeImage{}, imageError(CodeVerificationMissing, "The runtime image selector is incomplete.", "Install and verify exactly one role image before starting a session.", nil)
	}
	if err := ctx.Err(); err != nil {
		return RuntimeImage{}, contextError(ctx, err)
	}
	digestRoot := filepath.Join(cache.root, "sha256")
	children, err := os.ReadDir(digestRoot)
	if err != nil {
		return RuntimeImage{}, imageError(CodeCacheInvalid, "The immutable image cache could not be enumerated.", "Repair the image cache ownership and retry.", err)
	}
	var selected *RuntimeImage
	for _, child := range children {
		if err := ctx.Err(); err != nil {
			return RuntimeImage{}, contextError(ctx, err)
		}
		name := child.Name()
		if !cacheDigestDirectoryPattern.MatchString(name) {
			if strings.HasPrefix(name, ".partial-") {
				continue
			}
			return RuntimeImage{}, imageError(CodeCacheInvalid, "The image cache contains an unexpected execution entry.", "Remove only a separately verified invalid cache entry, then pull the image again.", nil)
		}
		if !child.IsDir() {
			return RuntimeImage{}, imageError(CodeCacheInvalid, "An immutable image digest entry has an unsafe type.", "Remove only a separately verified invalid cache entry, then pull the image again.", nil)
		}
		digest := "sha256:" + name
		entry, present, err := cache.load(ctx, digest, DefaultLimits())
		if err != nil {
			return RuntimeImage{}, err
		}
		if !present {
			continue
		}
		manifestBytes, err := readVerificationFile(ctx, entry.ManifestPath, DefaultVerificationLimits().MaxManifestBytes, CodeManifestContract, CodeManifestContract)
		if err != nil {
			return RuntimeImage{}, err
		}
		manifest, err := decodeManifest(manifestBytes, DefaultVerificationLimits().MaxJSONDepth)
		if err != nil {
			return RuntimeImage{}, err
		}
		bundle := ""
		if manifest.Bundle != nil {
			bundle = *manifest.Bundle
		}
		if manifest.Role != selector.Role || bundle != selector.Bundle {
			continue
		}
		if err := verifier.Verify(ctx, entry); err != nil {
			return RuntimeImage{}, err
		}
		if manifest.VirtualSizeBytes <= 0 {
			return RuntimeImage{}, imageError(CodeManifestContract, "The verified image has no usable virtual size.", "Pull a complete official role image.", nil)
		}
		candidate := RuntimeImage{
			Entry: entry, ManifestDigest: digest, ImageDigest: manifest.ImageDigest,
			SourceCommit: manifest.SourceCommit, Capabilities: append([]string(nil), manifest.Capabilities...),
			VirtualSizeBytes: uint64(manifest.VirtualSizeBytes),
		}
		if selected != nil {
			return RuntimeImage{}, imageError(CodeCacheConflict, "More than one verified image matches the requested role.", "Keep exactly one approved immutable role image in the execution cache.", nil)
		}
		selected = &candidate
	}
	if selected == nil {
		return RuntimeImage{}, imageError(CodeVerificationMissing, "No verified cached image matches the requested role.", "Pull and verify the exact role image before starting a session.", fs.ErrNotExist)
	}
	return *selected, nil
}
