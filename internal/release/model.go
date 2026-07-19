package release

import (
	"regexp"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

const (
	SchemaVersion        = 1
	OfficialRepository   = "StevenBuglione/private-vm"
	OfficialRepositoryID = "1305109560"
	OfficialOwnerID      = "34593055"
	OfficialWorkflow     = ".github/workflows/release.yml"
	MaximumArtifactBytes = int64(512 << 20)
	MaximumEvidenceBytes = int64(16 << 20)
	DefaultTimeout       = 30 * time.Minute
)

var (
	tagPattern    = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.(0|[1-9][0-9]*))?$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	numberPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

type ArtifactKind string

const (
	ArtifactDEB     ArtifactKind = "deb"
	ArtifactRPM     ArtifactKind = "rpm"
	ArtifactGeneric ArtifactKind = "generic-archive"
)

var artifactKinds = []ArtifactKind{ArtifactDEB, ArtifactRPM, ArtifactGeneric}

// PackageArtifact binds one public package byte stream to its SPDX document,
// build manifest and offline Sigstore bundle.
type PackageArtifact struct {
	Kind           ArtifactKind `json:"kind"`
	File           string       `json:"file"`
	SizeBytes      int64        `json:"size_bytes"`
	SHA256         string       `json:"sha256"`
	Manifest       string       `json:"manifest"`
	ManifestSHA256 string       `json:"manifest_sha256"`
	SBOM           string       `json:"sbom"`
	SBOMSHA256     string       `json:"sbom_sha256"`
	Provenance     string       `json:"provenance"`
}

// ImageArtifact records the immutable OCI manifest selected by the existing
// complete image verifier. Repository tags never become execution identities.
type ImageArtifact struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Digest     string `json:"manifest_digest"`
}

// Index is the closed whole-release identity. It contains no local paths,
// workflow output, credentials, filenames supplied by users or raw tool data.
type Index struct {
	SchemaVersion    int               `json:"schema_version"`
	Project          string            `json:"project"`
	ReleaseTag       string            `json:"release_tag"`
	SourceRepository string            `json:"source_repository"`
	SourceCommit     string            `json:"source_commit"`
	SourceRef        string            `json:"source_ref"`
	Workflow         string            `json:"workflow"`
	CreatedAt        string            `json:"created_at"`
	Packages         []PackageArtifact `json:"packages"`
	Images           []ImageArtifact   `json:"images"`
}

// PackageManifest is the canonical build contract placed beside each package.
type PackageManifest struct {
	SchemaVersion    int          `json:"schema_version"`
	Project          string       `json:"project"`
	ReleaseTag       string       `json:"release_tag"`
	Kind             ArtifactKind `json:"kind"`
	Artifact         string       `json:"artifact"`
	SizeBytes        int64        `json:"size_bytes"`
	SHA256           string       `json:"sha256"`
	SBOM             string       `json:"sbom"`
	SBOMSHA256       string       `json:"sbom_sha256"`
	SourceRepository string       `json:"source_repository"`
	SourceCommit     string       `json:"source_commit"`
	SourceRef        string       `json:"source_ref"`
	Workflow         string       `json:"workflow"`
	Architecture     string       `json:"architecture"`
	OS               string       `json:"os"`
}

type PrepareOptions struct {
	WorkDir, OutputDir                       string
	DEBPath, RPMPath, GenericPath            string
	ReleaseTag, SourceCommit, SourceRef      string
	RepositoryID, OwnerID, RunID, RunAttempt string
	Timeout                                  time.Duration
}

type PrepareResult struct {
	Index      Index
	Directory  string
	Predicates map[ArtifactKind]string
}

type PublishOptions struct {
	Directory    string
	ReleaseTag   string
	SourceCommit string
	Provenance   map[ArtifactKind]string
	Token        *secret.Bytes
	Timeout      time.Duration
}

type PublishResult struct {
	SchemaVersion int    `json:"schema_version"`
	Project       string `json:"project"`
	ReleaseTag    string `json:"release_tag"`
	SourceCommit  string `json:"source_commit"`
	Published     bool   `json:"published"`
	AssetCount    int    `json:"asset_count"`
}

type VerifyOptions struct {
	ReleaseTag   string
	SourceCommit string
	Timeout      time.Duration
}

type VerifyResult struct {
	SchemaVersion int    `json:"schema_version"`
	Project       string `json:"project"`
	ReleaseTag    string `json:"release_tag"`
	SourceCommit  string `json:"source_commit"`
	Verified      bool   `json:"verified"`
	PackageCount  int    `json:"package_count"`
	ImageCount    int    `json:"image_count"`
}
