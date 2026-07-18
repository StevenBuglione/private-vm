package image

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type Manifest struct {
	SchemaVersion      int      `json:"schema_version"`
	Project            string   `json:"project"`
	Role               string   `json:"role"`
	Bundle             *string  `json:"bundle"`
	Architecture       string   `json:"architecture"`
	SourceRepository   string   `json:"source_repository"`
	SourceCommit       string   `json:"source_commit"`
	SourceRef          string   `json:"source_ref"`
	Workflow           string   `json:"workflow"`
	ImageDigest        string   `json:"image_digest"`
	UncompressedSHA256 string   `json:"uncompressed_sha256"`
	NixOSVersion       string   `json:"nixos_version"`
	GuestAPIMajor      int      `json:"guest_api_major"`
	GuestAPIMinor      int      `json:"guest_api_minor"`
	Capabilities       []string `json:"capabilities"`
	SBOMDigest         string   `json:"sbom_digest"`
}

type TrustPolicy struct {
	Repository   string
	Workflow     string
	Architecture string
	Role         string
	APIMajor     int
}

func (m Manifest) Validate(policy TrustPolicy) error {
	if m.SchemaVersion != 1 || m.Project != "private-vm" {
		return errors.New("unsupported image manifest")
	}
	if m.SourceRepository != policy.Repository {
		return fmt.Errorf("repository mismatch: got %q", m.SourceRepository)
	}
	if m.Workflow != policy.Workflow {
		return fmt.Errorf("workflow mismatch: got %q", m.Workflow)
	}
	if m.Architecture != policy.Architecture {
		return fmt.Errorf("architecture mismatch: got %q", m.Architecture)
	}
	if m.Role != policy.Role {
		return fmt.Errorf("role mismatch: got %q", m.Role)
	}
	if m.GuestAPIMajor != policy.APIMajor {
		return fmt.Errorf("guest API major mismatch: got %d", m.GuestAPIMajor)
	}
	if !validDigest(m.ImageDigest) || !validDigest(m.SBOMDigest) {
		return errors.New("invalid OCI digest")
	}
	if !validHex(m.UncompressedSHA256, 32) || !validHex(m.SourceCommit, 20) {
		return errors.New("invalid source or image hash")
	}
	return nil
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	return validHex(strings.TrimPrefix(value, "sha256:"), 32)
}

func validHex(value string, bytes int) bool {
	if len(value) != bytes*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
