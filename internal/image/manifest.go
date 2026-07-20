package image

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	manifestSchemaVersion = 1
	frozenNixOSVersion    = "26.05"
	frozenQEMUMinimum     = "9.2"
	imageSPDXID           = "SPDXRef-IMAGE"
	imageFileSPDXID       = "SPDXRef-IMAGE-QCOW2"
)

var (
	commitPattern       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repositoryPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
	sourceRefPattern    = regexp.MustCompile(`^refs/(heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]*$`)
	workflowPattern     = regexp.MustCompile(`^\.github/workflows/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.ya?ml$`)
	spdxIDPattern       = regexp.MustCompile(`^SPDXRef-[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)
	nixStorePathPattern = regexp.MustCompile(`^file:///nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._=-]{1,160}$`)
	versionInfoPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,127}$`)
)

// Manifest is the exact frozen-v1 published image-manifest contract. Its JSON
// field set is kept identical to schemas/image-manifest.schema.json.
type Manifest struct {
	SchemaVersion         int      `json:"schema_version"`
	Project               string   `json:"project"`
	Role                  string   `json:"role"`
	Bundle                *string  `json:"bundle"`
	Architecture          string   `json:"architecture"`
	SourceRepository      string   `json:"source_repository"`
	SourceCommit          string   `json:"source_commit"`
	SourceRef             string   `json:"source_ref"`
	Workflow              string   `json:"workflow"`
	ImageDigest           string   `json:"image_digest"`
	UncompressedSHA256    string   `json:"uncompressed_sha256"`
	CompressedSizeBytes   int64    `json:"compressed_size_bytes"`
	UncompressedSizeBytes int64    `json:"uncompressed_size_bytes"`
	VirtualSizeBytes      int64    `json:"virtual_size_bytes"`
	NixOSVersion          string   `json:"nixos_version"`
	FlakeLockSHA256       string   `json:"flake_lock_sha256"`
	GuestAPIMajor         int      `json:"guest_api_major"`
	GuestAPIMinor         int      `json:"guest_api_minor"`
	MinimumQEMUVersion    string   `json:"minimum_qemu_version"`
	Capabilities          []string `json:"capabilities"`
	SBOMDigest            string   `json:"sbom_digest"`
	BuiltAt               string   `json:"built_at"`
}

var manifestFields = []string{
	"schema_version", "project", "role", "bundle", "architecture",
	"source_repository", "source_commit", "source_ref", "workflow",
	"image_digest", "uncompressed_sha256", "compressed_size_bytes",
	"uncompressed_size_bytes", "virtual_size_bytes", "nixos_version",
	"flake_lock_sha256", "guest_api_major", "guest_api_minor",
	"minimum_qemu_version", "capabilities", "sbom_digest", "built_at",
}

// CompatibilityPolicy is copied into the verifier. HostArchitecture uses Go's
// amd64/arm64 names; the image manifest uses OCI/Nix x86_64/aarch64 names.
type CompatibilityPolicy struct {
	Role                 string
	Bundle               string
	HostArchitecture     string
	GuestAPIMajor        int
	GuestAPIMinor        int
	MinimumGuestAPIMinor int
	HostQEMUVersion      string
	NixOSVersion         string
	Limits               VerificationLimits
}

type VerificationLimits struct {
	MaxManifestBytes           int64
	MaxSBOMBytes               int64
	MaxProvenanceBytes         int64
	MaxProvenancePayloadBytes  int64
	MaxTransparencyProofHashes int
	MaxPackages                int
	MaxFiles                   int
	MaxRelationships           int
	MaxJSONDepth               int
	Timeout                    time.Duration
}

func DefaultVerificationLimits() VerificationLimits {
	return VerificationLimits{
		MaxManifestBytes:           64 << 10,
		MaxSBOMBytes:               16 << 20,
		MaxProvenanceBytes:         4 << 20,
		MaxProvenancePayloadBytes:  256 << 10,
		MaxTransparencyProofHashes: 64,
		MaxPackages:                50_000,
		MaxFiles:                   4_096,
		MaxRelationships:           60_000,
		MaxJSONDepth:               32,
		Timeout:                    30 * time.Second,
	}
}

func (limits VerificationLimits) validate() error {
	if limits.MaxManifestBytes < 1 || limits.MaxManifestBytes > 1<<20 ||
		limits.MaxSBOMBytes < 1 || limits.MaxSBOMBytes > 64<<20 ||
		limits.MaxProvenanceBytes < 1 || limits.MaxProvenanceBytes > 16<<20 ||
		limits.MaxProvenancePayloadBytes < 1 || limits.MaxProvenancePayloadBytes > 1<<20 ||
		limits.MaxTransparencyProofHashes < 1 || limits.MaxTransparencyProofHashes > 128 ||
		limits.MaxPackages < 2 || limits.MaxPackages > 100_000 ||
		limits.MaxFiles < 1 || limits.MaxFiles > 100_000 ||
		limits.MaxRelationships < 3 || limits.MaxRelationships > 200_000 ||
		limits.MaxJSONDepth < 4 || limits.MaxJSONDepth > 64 ||
		limits.Timeout < time.Millisecond || limits.Timeout > 2*time.Minute {
		return imageError(
			CodeArtifactLimit,
			"The image verification limits are outside the supported bounds.",
			"Use finite IMG-002 limits no larger than the documented hard ceilings.",
			nil,
		)
	}
	return nil
}

type compatibilitySnapshot struct {
	role                 string
	bundle               string
	architecture         string
	guestAPIMajor        int
	guestAPIMinor        int
	minimumGuestAPIMinor int
	hostQEMUVersion      version
	nixosVersion         string
	limits               VerificationLimits
}

func snapshotPolicy(policy CompatibilityPolicy) (compatibilitySnapshot, error) {
	if err := policy.Limits.validate(); err != nil {
		return compatibilitySnapshot{}, err
	}
	architecture, ok := mapHostArchitecture(policy.HostArchitecture)
	if !ok {
		return compatibilitySnapshot{}, imageError(
			CodeArchitectureMismatch,
			"The host architecture has no frozen-v1 image mapping.",
			"Use an amd64 or arm64 Linux host and its matching signed image.",
			nil,
		)
	}
	if !validRoleBundle(policy.Role, policy.Bundle) || policy.GuestAPIMajor != 1 ||
		policy.MinimumGuestAPIMinor < 0 || policy.GuestAPIMinor < policy.MinimumGuestAPIMinor || policy.GuestAPIMinor > 65_535 ||
		policy.NixOSVersion != frozenNixOSVersion {
		return compatibilitySnapshot{}, imageError(
			CodeManifestContract,
			"The immutable host image policy is invalid.",
			"Install matching private-vm components with the frozen NixOS, role, bundle and guest API policy.",
			nil,
		)
	}
	hostQEMU, err := parseVersion(policy.HostQEMUVersion)
	if err != nil || hostQEMU.less(version{major: 9, minor: 2}) {
		return compatibilitySnapshot{}, imageError(
			CodeQEMUVersionMismatch,
			"The host QEMU version does not satisfy the frozen-v1 minimum.",
			"Install QEMU 9.2 or newer and rerun host diagnostics.",
			err,
		)
	}
	return compatibilitySnapshot{
		role: policy.Role, bundle: policy.Bundle, architecture: architecture,
		guestAPIMajor: policy.GuestAPIMajor, guestAPIMinor: policy.GuestAPIMinor,
		minimumGuestAPIMinor: policy.MinimumGuestAPIMinor, hostQEMUVersion: hostQEMU,
		nixosVersion: policy.NixOSVersion, limits: policy.Limits,
	}, nil
}

func mapHostArchitecture(value string) (string, bool) {
	switch value {
	case "amd64":
		return "x86_64", true
	case "arm64":
		return "aarch64", true
	default:
		return "", false
	}
}

func validRoleBundle(role, bundle string) bool {
	switch role {
	case "workstation":
		return bundle == "basic" || bundle == "office" || bundle == "development"
	case "downloader", "scanner", "exporter":
		return bundle == ""
	default:
		return false
	}
}

var roleCapabilities = map[string][]string{
	"workstation": {"desktop", "guest-events", "guest-shutdown", "guest-status", "network-warning", "vpn-verification", "wireguard-config", "workspace-export", "workspace-import"},
	"downloader":  {"guest-events", "guest-shutdown", "guest-status", "quarantine-seal", "torrent-download", "torrent-metadata", "vpn-verification", "wireguard-config"},
	"scanner":     {"approved-export", "definitions-update", "guest-events", "guest-shutdown", "guest-status", "inventory", "offline-verification", "reconstruct", "scan", "scan-report", "vpn-verification", "wireguard-config"},
	"exporter":    {"guest-events", "guest-shutdown", "guest-status", "usb-finalize", "usb-inspect", "usb-prepare", "usb-verify", "usb-write"},
}

func decodeManifest(data []byte, maximumDepth int) (Manifest, error) {
	var manifest Manifest
	if err := decodeClosedJSON(data, maximumDepth, manifestFields, &manifest); err != nil {
		return Manifest{}, imageError(
			CodeManifestContract,
			"The published image manifest is not a closed frozen-v1 document.",
			"Publish every required schema field exactly once and remove unknown or trailing data.",
			err,
		)
	}
	return manifest, nil
}

func (manifest Manifest) validate(policy compatibilitySnapshot, record cacheRecord) error {
	if manifest.SchemaVersion != manifestSchemaVersion || manifest.Project != "private-vm" ||
		!commitPattern.MatchString(manifest.SourceCommit) ||
		!validSourceRef(manifest.SourceRef) ||
		!repositoryPattern.MatchString(manifest.SourceRepository) ||
		!workflowPattern.MatchString(manifest.Workflow) ||
		!validDigest(manifest.ImageDigest) || !validDigest(manifest.SBOMDigest) ||
		!validHex(manifest.UncompressedSHA256, 32) || !validHex(manifest.FlakeLockSHA256, 32) ||
		manifest.CompressedSizeBytes < 1 || manifest.CompressedSizeBytes > 64<<30 ||
		manifest.UncompressedSizeBytes < 1 || manifest.UncompressedSizeBytes > 2<<40 ||
		manifest.VirtualSizeBytes < manifest.UncompressedSizeBytes || manifest.VirtualSizeBytes > 2<<40 ||
		manifest.NixOSVersion != policy.nixosVersion || !validBuiltAt(manifest.BuiltAt) {
		return imageError(
			CodeManifestContract,
			"The published image manifest does not satisfy the frozen-v1 schema and build contract.",
			"Publish a complete schema-version-1 manifest from pinned NixOS source with canonical hashes, sizes and timestamps.",
			nil,
		)
	}
	if manifest.Role != policy.role {
		return imageError(CodeRoleMismatch, "The image role does not match the requested compartment.", "Pull the image published for the requested role.", nil)
	}
	if !manifestBundleMatches(manifest, policy) {
		return imageError(CodeBundleMismatch, "The image bundle does not match the requested workstation bundle.", "Pull the exact requested workstation bundle; non-workstation roles must use a null bundle.", nil)
	}
	if manifest.Architecture != policy.architecture {
		return imageError(CodeArchitectureMismatch, "The image architecture does not match the host architecture.", "Pull the image built for this host architecture.", nil)
	}
	if manifest.GuestAPIMajor != policy.guestAPIMajor ||
		manifest.GuestAPIMinor < policy.minimumGuestAPIMinor ||
		manifest.GuestAPIMinor > policy.guestAPIMinor {
		return imageError(CodeGuestAPIMismatch, "The image guest API is incompatible with this host.", "Install matching host components or pull an image with a supported guest API version.", nil)
	}
	minimumQEMU, err := parseVersion(manifest.MinimumQEMUVersion)
	if err != nil || minimumQEMU.less(version{major: 9, minor: 2}) || policy.hostQEMUVersion.less(minimumQEMU) {
		return imageError(CodeQEMUVersionMismatch, "The image QEMU requirement is invalid or exceeds the host version.", "Install a supported QEMU release or pull an image compatible with this host.", err)
	}
	if manifest.MinimumQEMUVersion != frozenQEMUMinimum {
		return imageError(CodeQEMUVersionMismatch, "The image does not declare the frozen-v1 QEMU minimum.", "Publish the image with minimum_qemu_version set to the documented frozen-v1 value.", nil)
	}
	if expected := roleCapabilities[manifest.Role]; !slices.Equal(manifest.Capabilities, expected) {
		return imageError(CodeCapabilityMismatch, "The image capability set is not the exact sorted role contract.", "Publish the role image with every required capability exactly once and no extras.", nil)
	}
	if err := validateManifestCacheBindings(manifest, record); err != nil {
		return err
	}
	return nil
}

func manifestBundleMatches(manifest Manifest, policy compatibilitySnapshot) bool {
	if manifest.Role == "workstation" {
		return manifest.Bundle != nil && *manifest.Bundle == policy.bundle && validRoleBundle(manifest.Role, *manifest.Bundle)
	}
	return manifest.Bundle == nil && policy.bundle == "" && validRoleBundle(manifest.Role, "")
}

func validateManifestCacheBindings(manifest Manifest, record cacheRecord) error {
	imageRecord, ok := cacheFileByMediaType(record, MediaTypeQCOW2Zstd)
	if !ok || imageRecord.SourceDigest != manifest.ImageDigest ||
		imageRecord.SourceSizeBytes != manifest.CompressedSizeBytes ||
		strings.TrimPrefix(imageRecord.InstalledDigest, "sha256:") != manifest.UncompressedSHA256 ||
		imageRecord.InstalledSizeBytes != manifest.UncompressedSizeBytes {
		return imageError(CodeDigestMismatch, "The image manifest does not bind the compressed and installed QCOW2 cache identities.", "Do not launch the image; publish a manifest generated from the exact OCI descriptor and installed QCOW2 bytes.", nil)
	}
	sbomRecord, ok := cacheFileByMediaType(record, MediaTypeSBOM)
	if !ok || sbomRecord.SourceDigest != manifest.SBOMDigest || sbomRecord.InstalledDigest != manifest.SBOMDigest ||
		sbomRecord.SourceSizeBytes != sbomRecord.InstalledSizeBytes {
		return imageError(CodeDigestMismatch, "The image manifest does not bind the installed SPDX layer identity.", "Publish the exact SPDX document referenced by sbom_digest.", nil)
	}
	return nil
}

func cacheFileByMediaType(record cacheRecord, mediaType string) (cacheFileRecord, bool) {
	for _, file := range record.Files {
		if file.MediaType == mediaType {
			return file, true
		}
	}
	return cacheFileRecord{}, false
}

func validSourceRef(value string) bool {
	if len(value) < len("refs/tags/x") || len(value) > 255 || !sourceRefPattern.MatchString(value) ||
		strings.Contains(value, "..") || strings.Contains(value, "//") || strings.Contains(value, "@{") ||
		strings.Contains(value, "\\") || strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".") ||
		strings.HasSuffix(value, ".lock") {
		return false
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune("~^:?*[", r) {
			return false
		}
	}
	return true
}

func validBuiltAt(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && strings.HasSuffix(value, "Z") && parsed.UTC().Format(time.RFC3339) == value
}

type version struct{ major, minor, patch int }

func parseVersion(value string) (version, error) {
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return version{}, errors.New("invalid version component count")
	}
	values := [3]int{}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return version{}, errors.New("noncanonical version component")
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 || number > 10_000 {
			return version{}, errors.New("invalid version component")
		}
		values[index] = number
	}
	return version{major: values[0], minor: values[1], patch: values[2]}, nil
}

func (left version) less(right version) bool {
	if left.major != right.major {
		return left.major < right.major
	}
	if left.minor != right.minor {
		return left.minor < right.minor
	}
	return left.patch < right.patch
}

func validDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validHex(strings.TrimPrefix(value, "sha256:"), 32)
}

func validHex(value string, bytes int) bool {
	if len(value) != bytes*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func readVerificationFile(ctx context.Context, path string, maximum int64, missingCode, invalidCode ErrorCode) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, contextError(ctx, err)
	}
	file, err := os.Open(path)
	if err != nil {
		code := invalidCode
		message := "A required image verification document could not be opened."
		remediation := "Pull the complete image artifact again by immutable digest."
		if errors.Is(err, os.ErrNotExist) && missingCode != "" {
			code = missingCode
			message = "The official image is missing a required verification document."
			remediation = "Use an official strict artifact containing both the manifest and SPDX SBOM."
		}
		return nil, imageError(code, message, remediation, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, contextError(ctx, imageError(invalidCode, "A required image verification document could not be read.", "Pull the complete image artifact again by immutable digest.", err))
	}
	if int64(len(data)) > maximum {
		return nil, imageError(CodeArtifactLimit, "An image verification document exceeds its byte limit.", "Publish a bounded manifest and SPDX document within the frozen-v1 limits.", nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, contextError(ctx, err)
	}
	return data, nil
}

func decodeClosedJSON(data []byte, maximumDepth int, requiredTopLevel []string, destination any) error {
	if len(data) == 0 {
		return errors.New("empty JSON document")
	}
	if err := rejectDuplicateJSONKeys(data, maximumDepth); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || len(fields) != len(requiredTopLevel) {
		return errors.New("missing required top-level field")
	}
	for _, field := range requiredTopLevel {
		if _, ok := fields[field]; !ok {
			return fmt.Errorf("missing required field %q", field)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON document")
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte, maximumDepth int) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0, maximumDepth); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth, maximumDepth int) error {
	if depth > maximumDepth {
		return errors.New("JSON nesting depth exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1, maximumDepth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("malformed JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1, maximumDepth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("malformed JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
