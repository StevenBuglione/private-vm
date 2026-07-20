package release

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/StevenBuglione/private-vm/internal/image"
	"github.com/StevenBuglione/private-vm/internal/secret"
)

const maximumGitHubResponse = 1 << 20

type provenanceVerifier interface {
	Verify(context.Context, []byte, PackageManifest) error
}

type officialProvenanceVerifier struct{}

func (officialProvenanceVerifier) Verify(ctx context.Context, bundle []byte, manifest PackageManifest) error {
	return image.VerifyOfficialArtifactProvenance(ctx, bundle, image.OfficialArtifactProvenance{
		SubjectName: manifest.Artifact, Digest: manifest.SHA256,
		SourceCommit: manifest.SourceCommit, SourceRef: manifest.SourceRef,
	})
}

type releasePublisher interface {
	CreateDraft(context.Context, string, string) (int64, string, error)
	Upload(context.Context, int64, string, releaseAsset) error
	Publish(context.Context, int64) error
	DeleteDraft(context.Context, int64) error
}

type githubPublisher struct {
	client *http.Client
	token  *secret.Bytes
}

type githubRelease struct {
	ID        int64  `json:"id"`
	UploadURL string `json:"upload_url"`
}

// Publish validates every package and offline attestation before creating a
// draft GitHub Release. A partial draft is deleted before failure is returned.
func Publish(ctx context.Context, options PublishOptions) (PublishResult, error) {
	client := &http.Client{Timeout: boundedTimeout(options.Timeout)}
	return publish(ctx, options, &githubPublisher{client: client, token: options.Token}, officialProvenanceVerifier{})
}

func publish(ctx context.Context, options PublishOptions, publisher releasePublisher, verifier provenanceVerifier) (result PublishResult, returnedErr error) {
	if !filepath.IsAbs(options.Directory) || filepath.Clean(options.Directory) != options.Directory || options.Directory == "/" ||
		!tagPattern.MatchString(options.ReleaseTag) || !commitPattern.MatchString(options.SourceCommit) || publisher == nil || verifier == nil || options.Token == nil {
		return PublishResult{}, releaseError(CodeInvalid, "The release publication request is incomplete or unsafe.", "Use the protected release workflow and pass the credential only on standard input.", nil)
	}
	timeout := boundedTimeout(options.Timeout)
	publishCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		if cleanupErr := removeOwnedTree(options.Directory); cleanupErr != nil {
			result = PublishResult{}
			returnedErr = releaseError(CodeCleanupIncomplete, "The local release staging tree could not be removed completely.", "Remove only the owner-controlled staging directory before another release attempt.", errors.Join(returnedErr, cleanupErr))
		}
	}()

	index, assets, err := loadPreparedRelease(publishCtx, options, verifier)
	if err != nil {
		return PublishResult{}, contextReleaseError(publishCtx, err)
	}
	releaseID, uploadURL, err := publisher.CreateDraft(publishCtx, options.ReleaseTag, options.SourceCommit)
	if err != nil {
		return PublishResult{}, contextReleaseError(publishCtx, err)
	}
	draft := true
	defer func() {
		if draft {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			if cleanupErr := publisher.DeleteDraft(cleanupCtx, releaseID); cleanupErr != nil {
				result = PublishResult{}
				returnedErr = releaseError(CodeCleanupIncomplete, "A partial draft release could not be rolled back completely.", "Delete only the unpublished draft for this tag, retain the Git tag, and start a new run attempt.", errors.Join(returnedErr, cleanupErr))
			}
		}
	}()
	for _, asset := range assets {
		if err := publisher.Upload(publishCtx, releaseID, uploadURL, asset); err != nil {
			return PublishResult{}, contextReleaseError(publishCtx, releaseError(CodePublishFailed, "A bounded release asset upload failed.", "Let the cleanup owner remove the draft, then start a new run attempt.", err))
		}
	}
	if err := publisher.Publish(publishCtx, releaseID); err != nil {
		return PublishResult{}, contextReleaseError(publishCtx, releaseError(CodePublishFailed, "The complete draft release could not be made immutable and public.", "Let rollback remove the draft, then use a new run attempt.", err))
	}
	draft = false
	return PublishResult{SchemaVersion: SchemaVersion, Project: "private-vm", ReleaseTag: index.ReleaseTag, SourceCommit: index.SourceCommit, Published: true, AssetCount: len(assets)}, nil
}

type releaseAsset struct {
	name string
	path string
	size int64
}

func loadPreparedRelease(ctx context.Context, options PublishOptions, verifier provenanceVerifier) (Index, []releaseAsset, error) {
	indexBytes, err := readBounded(filepath.Join(options.Directory, "release-index.json"), MaximumEvidenceBytes)
	if err != nil {
		return Index{}, nil, releaseError(CodeArtifactInvalid, "The release index is missing or unsafe.", "Run prepare again from the protected tag.", err)
	}
	var index Index
	if err := decodeClosed(indexBytes, &index); err != nil || validateIndex(index, options.ReleaseTag, options.SourceCommit) != nil {
		return Index{}, nil, releaseError(CodeArtifactInvalid, "The release index is malformed or does not match this publication.", "Run prepare again for this exact tag and commit.", err)
	}
	assets := []releaseAsset{{name: "release-index.json", path: filepath.Join(options.Directory, "release-index.json"), size: int64(len(indexBytes))}}
	for _, expected := range index.Packages {
		manifestBytes, err := readBounded(filepath.Join(options.Directory, expected.Manifest), MaximumEvidenceBytes)
		if err != nil || digestBytes(manifestBytes) != expected.ManifestSHA256 {
			return Index{}, nil, releaseError(CodeArtifactInvalid, "A package build manifest does not match the release index.", "Rebuild all package release evidence.", err)
		}
		var manifest PackageManifest
		if err := decodeClosed(manifestBytes, &manifest); err != nil || validatePackageManifest(manifest, expected, index) != nil {
			return Index{}, nil, releaseError(CodeArtifactInvalid, "A package build manifest violates the frozen contract.", "Rebuild all package release evidence.", err)
		}
		sbomBytes, err := readBounded(filepath.Join(options.Directory, expected.SBOM), MaximumEvidenceBytes)
		if err != nil || digestBytes(sbomBytes) != expected.SBOMSHA256 || expected.SBOMSHA256 != manifest.SBOMSHA256 {
			return Index{}, nil, releaseError(CodeArtifactInvalid, "A package SPDX document does not match its immutable manifest.", "Rebuild package SBOM evidence.", err)
		}
		size, digest, err := hashFile(ctx, filepath.Join(options.Directory, expected.File), MaximumArtifactBytes)
		if err != nil || size != expected.SizeBytes || digest != expected.SHA256 || digest != manifest.SHA256 {
			return Index{}, nil, releaseError(CodeArtifactInvalid, "A package byte stream does not match its immutable manifest.", "Rebuild the package artifact from the protected tag.", err)
		}
		provenancePath, ok := options.Provenance[expected.Kind]
		if !ok {
			return Index{}, nil, releaseError(CodeProvenanceInvalid, "A package has no offline Sigstore bundle.", "Attest every exact package subject in the protected release environment.", nil)
		}
		provenanceBytes, err := readBounded(provenancePath, MaximumEvidenceBytes)
		if err != nil {
			return Index{}, nil, releaseError(CodeProvenanceInvalid, "A package Sigstore bundle did not pass official offline verification.", "Do not publish; attest the exact subject from the protected workflow.", err)
		}
		if verifyErr := verifier.Verify(ctx, provenanceBytes, manifest); verifyErr != nil {
			return Index{}, nil, releaseError(CodeProvenanceInvalid, "A package Sigstore bundle did not pass official offline verification.", "Do not publish; attest the exact subject from the protected workflow.", verifyErr)
		}
		stagedProvenance := filepath.Join(options.Directory, expected.Provenance)
		if filepath.Clean(provenancePath) != stagedProvenance {
			if err := writeExclusive(stagedProvenance, provenanceBytes); err != nil {
				return Index{}, nil, releaseError(CodeProvenanceInvalid, "A verified provenance bundle could not be staged.", "Retry in a new private staging directory.", err)
			}
		}
		assets = append(assets,
			releaseAsset{name: expected.File, path: filepath.Join(options.Directory, expected.File), size: expected.SizeBytes},
			releaseAsset{name: expected.Manifest, path: filepath.Join(options.Directory, expected.Manifest), size: int64(len(manifestBytes))},
			releaseAsset{name: expected.SBOM, path: filepath.Join(options.Directory, expected.SBOM), size: int64(len(sbomBytes))},
			releaseAsset{name: expected.Provenance, path: filepath.Join(options.Directory, expected.Provenance), size: int64(len(provenanceBytes))},
		)
	}
	return index, assets, nil
}

func validateIndex(index Index, tag, commit string) error {
	if index.SchemaVersion != SchemaVersion || index.Project != "private-vm" || index.ReleaseTag != tag || index.SourceRepository != OfficialRepository || index.SourceCommit != commit || index.SourceRef != "refs/tags/"+tag || index.Workflow != OfficialWorkflow || len(index.Packages) != len(artifactKinds) || len(index.Images) != len(imageTargets) {
		return errors.New("release index identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339, index.CreatedAt); err != nil {
		return errors.New("release index timestamp is invalid")
	}
	for position, expectedKind := range artifactKinds {
		artifact := index.Packages[position]
		if artifact.Kind != expectedKind || !cleanName(artifact.File) || !cleanName(artifact.Manifest) || !cleanName(artifact.SBOM) || !cleanName(artifact.Provenance) || artifact.SizeBytes < 1 || artifact.SizeBytes > MaximumArtifactBytes || !digestPattern.MatchString(artifact.SHA256) || !digestPattern.MatchString(artifact.ManifestSHA256) || !digestPattern.MatchString(artifact.SBOMSHA256) {
			return errors.New("release package identity is invalid")
		}
	}
	for position, expected := range imageTargets {
		artifact := index.Images[position]
		if artifact.Name != expected.name || artifact.Repository != "ghcr.io/stevenbuglione/private-vm/"+expected.name || !digestPattern.MatchString(artifact.Digest) {
			return errors.New("release image identity is invalid")
		}
	}
	return nil
}

func validatePackageManifest(manifest PackageManifest, expected PackageArtifact, index Index) error {
	if manifest.SchemaVersion != SchemaVersion || manifest.Project != "private-vm" || manifest.ReleaseTag != index.ReleaseTag || manifest.Kind != expected.Kind || manifest.Artifact != expected.File || manifest.SizeBytes != expected.SizeBytes || manifest.SHA256 != expected.SHA256 || manifest.SBOM != expected.SBOM || manifest.SBOMSHA256 != expected.SBOMSHA256 || manifest.SourceRepository != OfficialRepository || manifest.SourceCommit != index.SourceCommit || manifest.SourceRef != index.SourceRef || manifest.Workflow != OfficialWorkflow || manifest.Architecture != "amd64" || manifest.OS != "linux" {
		return errors.New("package manifest identity is invalid")
	}
	return nil
}

func boundedTimeout(value time.Duration) time.Duration {
	if value < time.Second || value > time.Hour {
		return DefaultTimeout
	}
	return value
}

func (publisher *githubPublisher) do(ctx context.Context, method, endpoint, contentType string, body []byte, destination any) error {
	if publisher == nil || publisher.client == nil || publisher.token == nil || !strings.HasPrefix(endpoint, "https://") {
		return releaseError(CodePublishFailed, "The fixed GitHub release client is unavailable.", "Use the protected official release workflow.", nil)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return releaseError(CodePublishFailed, "The fixed GitHub request could not be constructed.", "Retry from the protected workflow.", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	err = publisher.token.WithReader(func(reader io.Reader) error {
		value, readErr := io.ReadAll(io.LimitReader(reader, 64<<10))
		if readErr != nil || len(value) == 0 {
			clear(value)
			return errors.New("credential unavailable")
		}
		request.Header.Set("Authorization", "Bearer "+string(value))
		clear(value)
		return nil
	})
	if err != nil {
		return releaseError(CodePublishFailed, "The bounded GitHub credential could not be read.", "Pass one ephemeral workflow token through standard input.", err)
	}
	response, err := publisher.client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		return releaseError(CodePublishFailed, "The GitHub release request failed.", "Retry the protected workflow; no remote response was trusted.", err)
	}
	defer response.Body.Close()
	responseBytes, readErr := io.ReadAll(io.LimitReader(response.Body, maximumGitHubResponse+1))
	if readErr != nil || len(responseBytes) > maximumGitHubResponse {
		return releaseError(CodePublishFailed, "The GitHub release response exceeded its bound.", "Retry the protected workflow.", readErr)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		code := CodePublishFailed
		if response.StatusCode == http.StatusUnprocessableEntity {
			code = CodeConflict
		}
		return releaseError(code, "GitHub refused the immutable release transaction.", "Never overwrite a release; use a new canonical tag or run attempt after cleanup.", nil)
	}
	if destination != nil && decodeClosed(responseBytes, destination) != nil {
		return releaseError(CodePublishFailed, "GitHub returned malformed release metadata.", "Retry the protected workflow.", nil)
	}
	return nil
}

func (publisher *githubPublisher) CreateDraft(ctx context.Context, tag, commit string) (int64, string, error) {
	body, _ := canonicalJSON(map[string]any{"tag_name": tag, "target_commitish": commit, "name": tag, "draft": true, "prerelease": strings.Contains(tag, "-rc.")})
	var release githubRelease
	if err := publisher.do(ctx, http.MethodPost, "https://api.github.com/repos/"+OfficialRepository+"/releases", "application/json", body, &release); err != nil {
		return 0, "", err
	}
	upload := strings.Split(release.UploadURL, "{")[0]
	if release.ID < 1 || upload != fmt.Sprintf("https://uploads.github.com/repos/%s/releases/%d/assets", OfficialRepository, release.ID) {
		return 0, "", releaseError(CodePublishFailed, "GitHub returned an unexpected release upload identity.", "Do not upload; retry from the official repository.", nil)
	}
	return release.ID, upload, nil
}

func (publisher *githubPublisher) Upload(ctx context.Context, id int64, uploadURL string, asset releaseAsset) error {
	if id < 1 || !cleanName(asset.name) || uploadURL != fmt.Sprintf("https://uploads.github.com/repos/%s/releases/%d/assets", OfficialRepository, id) || asset.size < 1 || asset.size > MaximumArtifactBytes {
		return releaseError(CodePublishFailed, "A release upload target is outside the frozen contract.", "Use only prepare-generated release assets.", nil)
	}
	file, info, err := openRegular(asset.path, MaximumArtifactBytes)
	if err != nil || info.Size() != asset.size {
		return releaseError(CodePublishFailed, "A release asset changed before upload.", "Abort publication and rebuild the complete staging set.", err)
	}
	defer file.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL+"?name="+url.QueryEscape(asset.name), file)
	if err != nil {
		return releaseError(CodePublishFailed, "The bounded upload request could not be constructed.", "Retry from the protected workflow.", err)
	}
	request.ContentLength = asset.size
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("Content-Type", "application/octet-stream")
	err = publisher.token.WithReader(func(reader io.Reader) error {
		value, readErr := io.ReadAll(io.LimitReader(reader, 64<<10))
		if readErr != nil || len(value) == 0 {
			clear(value)
			return errors.New("credential unavailable")
		}
		request.Header.Set("Authorization", "Bearer "+string(value))
		clear(value)
		return nil
	})
	if err != nil {
		return releaseError(CodePublishFailed, "The bounded GitHub credential could not be read.", "Pass one ephemeral workflow token through standard input.", err)
	}
	response, err := publisher.client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		return releaseError(CodePublishFailed, "The bounded GitHub upload failed.", "Retry after draft rollback.", err)
	}
	defer response.Body.Close()
	responseBytes, readErr := io.ReadAll(io.LimitReader(response.Body, maximumGitHubResponse+1))
	if readErr != nil || len(responseBytes) > maximumGitHubResponse || response.StatusCode < 200 || response.StatusCode >= 300 {
		return releaseError(CodePublishFailed, "GitHub refused a bounded release upload.", "Let rollback delete the draft, then retry.", readErr)
	}
	return nil
}

func (publisher *githubPublisher) Publish(ctx context.Context, id int64) error {
	body, _ := json.Marshal(map[string]bool{"draft": false})
	return publisher.do(ctx, http.MethodPatch, fmt.Sprintf("https://api.github.com/repos/%s/releases/%d", OfficialRepository, id), "application/json", body, nil)
}

func (publisher *githubPublisher) DeleteDraft(ctx context.Context, id int64) error {
	return publisher.do(ctx, http.MethodDelete, fmt.Sprintf("https://api.github.com/repos/%s/releases/%d", OfficialRepository, id), "", nil, nil)
}
