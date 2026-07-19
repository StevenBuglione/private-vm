package release

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/StevenBuglione/private-vm/internal/image"
)

type sourceRunner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type execSourceRunner struct{ directory string }

func (runner execSourceRunner) Run(ctx context.Context, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Dir = runner.directory
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"}
	output := newBoundedOutput(1 << 20)
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type boundedOutput struct {
	data    []byte
	maximum int
}

func newBoundedOutput(maximum int) *boundedOutput { return &boundedOutput{maximum: maximum} }

func (output *boundedOutput) Write(data []byte) (int, error) {
	length := len(data)
	if len(output.data)+length > output.maximum {
		return length, errors.New("release command output exceeded its bound")
	}
	output.data = append(output.data, data...)
	return length, nil
}

func (output *boundedOutput) Bytes() []byte { return append([]byte(nil), output.data...) }

type imageVerifier interface {
	Verify(context.Context, string, string, string) (string, error)
}

type officialImageVerifier struct{}

func (officialImageVerifier) Verify(ctx context.Context, tag, role, bundle string) (string, error) {
	name := role
	if bundle != "" {
		name += "-" + bundle
	}
	entry, err := image.VerifyAnonymousRelease(ctx, image.AnonymousVerifyOptions{
		Repository: "ghcr.io/stevenbuglione/private-vm/" + name,
		ReleaseTag: tag,
		Role:       role,
		Bundle:     bundle,
		Timeout:    DefaultTimeout,
	})
	return entry.ManifestDigest, err
}

type imageTarget struct{ name, role, bundle string }

var imageTargets = []imageTarget{
	{"workstation-basic", "workstation", "basic"},
	{"workstation-office", "workstation", "office"},
	{"workstation-development", "workstation", "development"},
	{"downloader", "downloader", ""},
	{"scanner", "scanner", ""},
	{"exporter", "exporter", ""},
}

// Prepare validates protected source state, copies exactly three package
// artifacts and anonymously verifies all six already-published images.
func Prepare(ctx context.Context, options PrepareOptions) (PrepareResult, error) {
	return prepare(ctx, options, execSourceRunner{directory: options.WorkDir}, officialImageVerifier{})
}

func prepare(ctx context.Context, options PrepareOptions, runner sourceRunner, images imageVerifier) (result PrepareResult, returnedErr error) {
	if err := validatePrepare(options); err != nil {
		return PrepareResult{}, err
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	prepareCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	createdAt, err := verifyProtectedSource(prepareCtx, options, runner)
	if err != nil {
		return PrepareResult{}, err
	}
	versionBytes, err := readBounded(filepath.Join(options.WorkDir, "VERSION"), 128)
	if err != nil || strings.TrimSpace(string(versionBytes)) != strings.TrimPrefix(options.ReleaseTag, "v") {
		return PrepareResult{}, releaseError(CodeSourceUnprotected, "The protected source version does not match the canonical release tag.", "Update and review VERSION before creating the protected tag.", err)
	}
	if err := os.Mkdir(options.OutputDir, 0o700); err != nil {
		return PrepareResult{}, releaseError(CodeInvalid, "The private release directory could not be created exclusively.", "Use a new owner-controlled staging path.", err)
	}
	keep := false
	defer func() {
		if !keep {
			if cleanupErr := removeOwnedTree(options.OutputDir); cleanupErr != nil {
				result = PrepareResult{}
				returnedErr = releaseError(CodeCleanupIncomplete, "The failed release staging tree could not be removed completely.", "Remove only the reported owner-controlled staging directory, then retry.", errors.Join(returnedErr, cleanupErr))
			}
		}
	}()

	version := strings.TrimPrefix(options.ReleaseTag, "v")
	sources := map[ArtifactKind]string{ArtifactDEB: options.DEBPath, ArtifactRPM: options.RPMPath, ArtifactGeneric: options.GenericPath}
	packages := make([]PackageArtifact, 0, len(artifactKinds))
	predicates := make(map[ArtifactKind]string, len(artifactKinds))
	for _, kind := range artifactKinds {
		if err := prepareCtx.Err(); err != nil {
			return PrepareResult{}, contextReleaseError(prepareCtx, err)
		}
		if !validArtifactInput(kind, sources[kind]) {
			return PrepareResult{}, releaseError(CodeArtifactInvalid, "A package input does not match its fixed release format.", "Pass the exact DEB, RPM and generic tar.zst outputs.", nil)
		}
		name := canonicalArtifactName(kind, version)
		size, digest, err := copyVerified(prepareCtx, sources[kind], filepath.Join(options.OutputDir, name), MaximumArtifactBytes)
		if err != nil {
			return PrepareResult{}, contextReleaseError(prepareCtx, releaseError(CodeArtifactInvalid, "A package artifact is missing, unsafe, changed or outside its byte bound.", "Rebuild the exact DEB, RPM and generic archive from the protected tag.", err))
		}
		sbomName := string(kind) + ".sbom.spdx.json"
		sbom, err := encodeSPDX(kind, name, version, digest, createdAt)
		if err != nil || writeExclusive(filepath.Join(options.OutputDir, sbomName), sbom) != nil {
			return PrepareResult{}, releaseError(CodeArtifactInvalid, "The package SPDX evidence could not be written.", "Rebuild release evidence in a new private staging directory.", err)
		}
		manifestName := string(kind) + ".build-manifest.json"
		manifest := PackageManifest{
			SchemaVersion: SchemaVersion, Project: "private-vm", ReleaseTag: options.ReleaseTag,
			Kind: kind, Artifact: name, SizeBytes: size, SHA256: digest,
			SBOM: sbomName, SBOMSHA256: digestBytes(sbom), SourceRepository: OfficialRepository,
			SourceCommit: options.SourceCommit, SourceRef: options.SourceRef, Workflow: OfficialWorkflow,
			Architecture: "amd64", OS: "linux",
		}
		manifestBytes, _ := canonicalJSON(manifest)
		if err := writeExclusive(filepath.Join(options.OutputDir, manifestName), manifestBytes); err != nil {
			return PrepareResult{}, releaseError(CodeArtifactInvalid, "The package build manifest could not be written.", "Rebuild release evidence in a new private staging directory.", err)
		}
		predicateName := string(kind) + ".predicate.json"
		predicate, err := encodePredicate(options)
		if err != nil || writeExclusive(filepath.Join(options.OutputDir, predicateName), predicate) != nil {
			return PrepareResult{}, releaseError(CodeArtifactInvalid, "The package provenance predicate could not be written.", "Use the protected release workflow with complete immutable identity.", err)
		}
		provenanceName := string(kind) + ".sigstore.json"
		packages = append(packages, PackageArtifact{
			Kind: kind, File: name, SizeBytes: size, SHA256: digest,
			Manifest: manifestName, ManifestSHA256: digestBytes(manifestBytes),
			SBOM: sbomName, SBOMSHA256: digestBytes(sbom), Provenance: provenanceName,
		})
		predicates[kind] = filepath.Join(options.OutputDir, predicateName)
	}

	verifiedImages := make([]ImageArtifact, 0, len(imageTargets))
	for _, target := range imageTargets {
		digest, err := images.Verify(prepareCtx, options.ReleaseTag, target.role, target.bundle)
		if err != nil || !digestPattern.MatchString(digest) {
			return PrepareResult{}, contextReleaseError(prepareCtx, releaseError(CodeVerifyFailed, "An official image did not pass anonymous immutable verification.", "Publish and anonymously verify all six image rows for the same protected tag before packages.", err))
		}
		verifiedImages = append(verifiedImages, ImageArtifact{Name: target.name, Repository: "ghcr.io/stevenbuglione/private-vm/" + target.name, Digest: digest})
	}
	index := Index{
		SchemaVersion: SchemaVersion, Project: "private-vm", ReleaseTag: options.ReleaseTag,
		SourceRepository: OfficialRepository, SourceCommit: options.SourceCommit,
		SourceRef: options.SourceRef, Workflow: OfficialWorkflow, CreatedAt: createdAt,
		Packages: packages, Images: verifiedImages,
	}
	indexBytes, _ := canonicalJSON(index)
	if err := writeExclusive(filepath.Join(options.OutputDir, "release-index.json"), indexBytes); err != nil {
		return PrepareResult{}, releaseError(CodeArtifactInvalid, "The whole-release index could not be written.", "Retry preparation in a new private staging directory.", err)
	}
	if err := syncDirectory(options.OutputDir); err != nil {
		return PrepareResult{}, releaseError(CodeArtifactInvalid, "The whole-release staging directory could not be synchronized.", "Retry preparation on a local filesystem.", err)
	}
	keep = true
	return PrepareResult{Index: index, Directory: options.OutputDir, Predicates: predicates}, nil
}

func validatePrepare(options PrepareOptions) error {
	if !tagPattern.MatchString(options.ReleaseTag) || options.SourceRef != "refs/tags/"+options.ReleaseTag || !commitPattern.MatchString(options.SourceCommit) ||
		options.RepositoryID != OfficialRepositoryID || options.OwnerID != OfficialOwnerID || !numberPattern.MatchString(options.RunID) || !numberPattern.MatchString(options.RunAttempt) {
		return releaseError(CodeInvalid, "The release identity is incomplete or not canonical SemVer/RC.", "Use the official protected tag workflow and immutable GitHub repository identifiers.", nil)
	}
	for _, path := range []string{options.WorkDir, options.OutputDir, options.DEBPath, options.RPMPath, options.GenericPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return releaseError(CodeInvalid, "A release path is not absolute, canonical and narrowly scoped.", "Pass exact source, staging and artifact paths.", nil)
		}
	}
	if options.Timeout < 0 || options.Timeout > time.Hour {
		return releaseError(CodeInvalid, "The release timeout is outside its finite bound.", "Use a timeout no greater than one hour.", nil)
	}
	return nil
}

func verifyProtectedSource(ctx context.Context, options PrepareOptions, runner sourceRunner) (string, error) {
	checks := []struct {
		arguments []string
		expected  string
	}{
		{[]string{"rev-parse", "HEAD"}, options.SourceCommit},
		{[]string{"rev-list", "-n", "1", options.ReleaseTag}, options.SourceCommit},
		{[]string{"remote", "get-url", "origin"}, "https://github.com/" + OfficialRepository},
		{[]string{"status", "--porcelain=v1", "--untracked-files=all"}, ""},
	}
	for _, check := range checks {
		output, err := runner.Run(ctx, check.arguments...)
		if err != nil || strings.TrimSpace(string(output)) != check.expected {
			return "", contextReleaseError(ctx, releaseError(CodeSourceUnprotected, "The source is dirty, non-official or the tag does not identify this commit.", "Release only an approved protected main commit through its canonical tag.", err))
		}
	}
	if _, err := runner.Run(ctx, "merge-base", "--is-ancestor", options.SourceCommit, "refs/remotes/origin/main"); err != nil {
		return "", contextReleaseError(ctx, releaseError(CodeSourceUnprotected, "The release commit is not reachable from fetched official main.", "Fetch protected origin/main and tag an approved main commit.", err))
	}
	timestamp, err := runner.Run(ctx, "show", "-s", "--format=%ct", options.SourceCommit)
	seconds, parseErr := strconv.ParseInt(strings.TrimSpace(string(timestamp)), 10, 64)
	if err != nil || parseErr != nil || seconds < 1 {
		return "", contextReleaseError(ctx, releaseError(CodeSourceUnprotected, "The source commit timestamp could not be verified.", "Use a complete protected Git checkout.", errors.Join(err, parseErr)))
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339), nil
}

func canonicalArtifactName(kind ArtifactKind, version string) string {
	suffix := map[ArtifactKind]string{ArtifactDEB: ".deb", ArtifactRPM: ".rpm", ArtifactGeneric: ".tar.zst"}[kind]
	return "private-vm_" + version + "_linux_amd64" + suffix
}

func validArtifactInput(kind ArtifactKind, path string) bool {
	suffix := map[ArtifactKind]string{ArtifactDEB: ".deb", ArtifactRPM: ".rpm", ArtifactGeneric: ".tar.zst"}[kind]
	return suffix != "" && strings.HasSuffix(filepath.Base(path), suffix)
}

type spdxDocument struct {
	SPDXVersion       string `json:"spdxVersion"`
	DataLicense       string `json:"dataLicense"`
	SPDXID            string `json:"SPDXID"`
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	CreationInfo      struct {
		Created  string   `json:"created"`
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	Packages      []spdxPackage      `json:"packages"`
	Files         []spdxFile         `json:"files"`
	Relationships []spdxRelationship `json:"relationships"`
}
type spdxPackage struct {
	Name             string         `json:"name"`
	SPDXID           string         `json:"SPDXID"`
	VersionInfo      string         `json:"versionInfo"`
	DownloadLocation string         `json:"downloadLocation"`
	FilesAnalyzed    bool           `json:"filesAnalyzed"`
	Checksums        []spdxChecksum `json:"checksums"`
}
type spdxFile struct {
	FileName  string         `json:"fileName"`
	SPDXID    string         `json:"SPDXID"`
	Checksums []spdxChecksum `json:"checksums"`
}
type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}
type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func encodeSPDX(kind ArtifactKind, name, version, digest, created string) ([]byte, error) {
	checksum := strings.TrimPrefix(digest, "sha256:")
	document := spdxDocument{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "private-vm-" + string(kind), DocumentNamespace: "https://github.com/StevenBuglione/private-vm/releases/" + version + "/" + string(kind)}
	document.CreationInfo.Created = created
	document.CreationInfo.Creators = []string{"Tool: private-vm release workflow"}
	document.Packages = []spdxPackage{{Name: "private-vm", SPDXID: "SPDXRef-Package-private-vm-" + string(kind), VersionInfo: version, DownloadLocation: "NOASSERTION", FilesAnalyzed: true, Checksums: []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: checksum}}}}
	document.Files = []spdxFile{{FileName: "./" + name, SPDXID: "SPDXRef-File-package", Checksums: []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: checksum}}}}
	document.Relationships = []spdxRelationship{
		{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: document.Packages[0].SPDXID},
		{SPDXElementID: document.Packages[0].SPDXID, RelationshipType: "CONTAINS", RelatedSPDXElement: "SPDXRef-File-package"},
	}
	return canonicalJSON(document)
}

func encodePredicate(options PrepareOptions) ([]byte, error) {
	repository := "https://github.com/" + OfficialRepository
	value := map[string]any{
		"buildDefinition": map[string]any{
			"buildType":            "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
			"externalParameters":   map[string]any{"workflow": map[string]any{"ref": options.SourceRef, "repository": repository, "path": "/" + OfficialWorkflow}},
			"internalParameters":   map[string]any{"github": map[string]any{"event_name": "push", "repository_id": options.RepositoryID, "repository_owner_id": options.OwnerID}},
			"resolvedDependencies": []any{map[string]any{"uri": "git+" + repository + "@" + options.SourceRef, "digest": map[string]any{"gitCommit": options.SourceCommit}}},
		},
		"runDetails": map[string]any{
			"builder":  map[string]any{"id": "https://github.com/actions/runner/github-hosted"},
			"metadata": map[string]any{"invocationId": fmt.Sprintf("%s/actions/runs/%s/attempts/%s", repository, options.RunID, options.RunAttempt)},
		},
	}
	return canonicalJSON(value)
}

func contextReleaseError(ctx context.Context, original error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return releaseError(CodeTimeout, "The bounded release operation timed out.", "Correct the blocked release dependency and create a new run attempt.", context.DeadlineExceeded)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return releaseError(CodeCancelled, "The release operation was cancelled.", "Confirm staging cleanup before retrying.", context.Canceled)
	}
	return original
}
