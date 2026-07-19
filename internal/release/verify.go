package release

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
)

type publicFetcher interface {
	Fetch(context.Context, string) (map[string][]byte, error)
}

type githubPublicFetcher struct{ client *http.Client }

type publicRelease struct {
	TagName string `json:"tag_name"`
	Draft   bool   `json:"draft"`
	Assets  []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Verify anonymously downloads the complete public GitHub Release, verifies
// all package bytes/evidence/provenance offline, then independently resolves
// and verifies all six public OCI images by immutable digest.
func Verify(ctx context.Context, options VerifyOptions) (VerifyResult, error) {
	client := &http.Client{Timeout: boundedTimeout(options.Timeout)}
	return verify(ctx, options, githubPublicFetcher{client: client}, officialProvenanceVerifier{}, officialImageVerifier{})
}

func verify(ctx context.Context, options VerifyOptions, fetcher publicFetcher, provenance provenanceVerifier, images imageVerifier) (result VerifyResult, returnedErr error) {
	if !tagPattern.MatchString(options.ReleaseTag) || !commitPattern.MatchString(options.SourceCommit) || fetcher == nil || provenance == nil || images == nil {
		return VerifyResult{}, releaseError(CodeInvalid, "The anonymous verification identity is incomplete.", "Pass the exact canonical tag and protected source commit.", nil)
	}
	verifyCtx, cancel := context.WithTimeout(ctx, boundedTimeout(options.Timeout))
	defer cancel()
	assets, err := fetcher.Fetch(verifyCtx, options.ReleaseTag)
	if err != nil {
		return VerifyResult{}, contextReleaseError(verifyCtx, releaseError(CodeVerifyFailed, "The public release assets could not be fetched anonymously.", "Make the release public and retry without credentials.", err))
	}
	root, err := os.MkdirTemp("", "private-vm-release-verify-")
	if err != nil {
		return VerifyResult{}, releaseError(CodeVerifyFailed, "A private verification directory could not be created.", "Use a local filesystem with an owner-controlled temporary directory.", err)
	}
	defer func() {
		if cleanupErr := removeOwnedTree(root); cleanupErr != nil {
			result = VerifyResult{}
			returnedErr = releaseError(CodeCleanupIncomplete, "The anonymous verification tree could not be removed completely.", "Remove only the owner-controlled verification directory before retrying.", errors.Join(returnedErr, cleanupErr))
		}
	}()
	if err := os.Chmod(root, 0o700); err != nil {
		return VerifyResult{}, releaseError(CodeVerifyFailed, "The private verification directory could not be secured.", "Use a local owner-controlled filesystem.", err)
	}
	for name, data := range assets {
		if !cleanName(name) || int64(len(data)) < 1 || int64(len(data)) > MaximumArtifactBytes {
			return VerifyResult{}, releaseError(CodeVerifyFailed, "A public release asset is unsafe or outside its byte bound.", "Do not install this release.", nil)
		}
		if err := writeExclusive(filepath.Join(root, name), data); err != nil {
			return VerifyResult{}, releaseError(CodeVerifyFailed, "A public release asset could not be staged safely.", "Retry verification on a local filesystem.", err)
		}
	}
	indexBytes, ok := assets["release-index.json"]
	if !ok {
		return VerifyResult{}, releaseError(CodeVerifyFailed, "The public release has no whole-release index.", "Do not install an incomplete release.", nil)
	}
	var index Index
	if err := decodeClosed(indexBytes, &index); err != nil || validateIndex(index, options.ReleaseTag, options.SourceCommit) != nil {
		return VerifyResult{}, releaseError(CodeVerifyFailed, "The public release index violates its closed identity contract.", "Do not install this release.", err)
	}
	provenancePaths := make(map[ArtifactKind]string, len(index.Packages))
	expected := map[string]struct{}{"release-index.json": {}}
	for _, artifact := range index.Packages {
		provenancePaths[artifact.Kind] = filepath.Join(root, artifact.Provenance)
		for _, name := range []string{artifact.File, artifact.Manifest, artifact.SBOM, artifact.Provenance} {
			expected[name] = struct{}{}
		}
	}
	if len(assets) != len(expected) {
		return VerifyResult{}, releaseError(CodeVerifyFailed, "The public release contains a missing or unexpected asset.", "Do not install a release whose asset set differs from its closed index.", nil)
	}
	if _, _, err := loadPreparedRelease(verifyCtx, PublishOptions{Directory: root, ReleaseTag: options.ReleaseTag, SourceCommit: options.SourceCommit, Provenance: provenancePaths}, provenance); err != nil {
		return VerifyResult{}, contextReleaseError(verifyCtx, releaseError(CodeVerifyFailed, "A public package failed digest, SPDX, manifest or provenance verification.", "Do not install this release.", err))
	}
	for position, target := range imageTargets {
		digest, err := images.Verify(verifyCtx, options.ReleaseTag, target.role, target.bundle)
		if err != nil || digest != index.Images[position].Digest {
			return VerifyResult{}, contextReleaseError(verifyCtx, releaseError(CodeVerifyFailed, "A public image failed verification or differs from the whole-release index.", "Do not use any artifact from this incomplete release.", err))
		}
	}
	return VerifyResult{SchemaVersion: SchemaVersion, Project: "private-vm", ReleaseTag: options.ReleaseTag, SourceCommit: options.SourceCommit, Verified: true, PackageCount: len(index.Packages), ImageCount: len(index.Images)}, nil
}

func (fetcher githubPublicFetcher) Fetch(ctx context.Context, tag string) (map[string][]byte, error) {
	if fetcher.client == nil || !tagPattern.MatchString(tag) {
		return nil, errors.New("public release fetch request is invalid")
	}
	endpoint := "https://api.github.com/repos/" + OfficialRepository + "/releases/tags/" + url.PathEscape(tag)
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := fetcher.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("public release metadata is unavailable")
	}
	metadata, err := io.ReadAll(io.LimitReader(response.Body, maximumGitHubResponse+1))
	if err != nil || len(metadata) > maximumGitHubResponse {
		return nil, errors.New("public release metadata exceeded its bound")
	}
	var release publicRelease
	if err := json.Unmarshal(metadata, &release); err != nil || release.TagName != tag || release.Draft || len(release.Assets) != 13 {
		return nil, errors.New("public release metadata violates the frozen contract")
	}
	sort.Slice(release.Assets, func(left, right int) bool { return release.Assets[left].Name < release.Assets[right].Name })
	result := make(map[string][]byte, len(release.Assets))
	for _, asset := range release.Assets {
		if !cleanName(asset.Name) || asset.Size < 1 || asset.Size > MaximumArtifactBytes {
			return nil, errors.New("public release asset metadata is unsafe")
		}
		expectedURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", OfficialRepository, tag, url.PathEscape(asset.Name))
		if asset.URL != expectedURL {
			return nil, errors.New("public release asset URL is unexpected")
		}
		assetRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
		assetResponse, err := fetcher.client.Do(assetRequest)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(assetResponse.Body, asset.Size+1))
		closeErr := assetResponse.Body.Close()
		if assetResponse.StatusCode != http.StatusOK || readErr != nil || closeErr != nil || int64(len(data)) != asset.Size {
			return nil, errors.New("public release asset transfer failed its exact size contract")
		}
		if _, duplicate := result[asset.Name]; duplicate {
			return nil, errors.New("public release contains a duplicate asset")
		}
		result[asset.Name] = data
	}
	return result, nil
}
