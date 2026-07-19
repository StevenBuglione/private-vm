package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// ProvenanceVerifier is the mandatory IMG-003 seam. IMG-002 deliberately does
// not provide an accepting implementation, so manifest/SBOM validation alone
// cannot be composed into a runnable official pull.
type ProvenanceVerifier interface {
	VerifyProvenance(context.Context, Entry, Manifest) error
}

type ProvenanceVerificationFunc func(context.Context, Entry, Manifest) error

func (function ProvenanceVerificationFunc) VerifyProvenance(ctx context.Context, entry Entry, manifest Manifest) error {
	if function == nil {
		return imageError(CodeVerificationMissing, "No image provenance verifier is available.", "Install IMG-003 repository and workflow provenance verification before pulling an official image.", nil)
	}
	return function(ctx, entry, manifest)
}

type officialVerifier struct {
	policy     compatibilitySnapshot
	provenance ProvenanceVerifier
}

// NewOfficialVerifier composes strict manifest/SBOM verification with the
// mandatory IMG-003 implementation. There is no official non-SBOM mode.
func NewOfficialVerifier(policy CompatibilityPolicy, provenance ProvenanceVerifier) (Verifier, error) {
	if nilLike(provenance) {
		return nil, imageError(CodeVerificationMissing, "No image provenance verifier is available.", "Install IMG-003 repository and workflow provenance verification before pulling an official image.", nil)
	}
	snapshot, err := snapshotPolicy(policy)
	if err != nil {
		return nil, err
	}
	return &officialVerifier{policy: snapshot, provenance: provenance}, nil
}

func (verifier *officialVerifier) Verify(ctx context.Context, entry Entry) error {
	if verifier == nil || nilLike(verifier.provenance) {
		return imageError(CodeVerificationMissing, "The complete official image verifier is unavailable.", "Install IMG-002 and IMG-003 verification components before pulling an official image.", nil)
	}
	verifyContext, cancel := context.WithTimeout(ctx, verifier.policy.limits.Timeout)
	defer cancel()
	if err := verifyContext.Err(); err != nil {
		return contextError(verifyContext, err)
	}

	record, err := readCacheRecord(entry.RecordPath)
	if err != nil {
		return err
	}
	manifestBytes, err := readVerificationFile(verifyContext, entry.ManifestPath, verifier.policy.limits.MaxManifestBytes, CodeManifestContract, CodeManifestContract)
	if err != nil {
		return err
	}
	if err := verifyDocumentRecord(manifestBytes, record, MediaTypeManifest); err != nil {
		return err
	}
	manifest, err := decodeManifest(manifestBytes, verifier.policy.limits.MaxJSONDepth)
	if err != nil {
		return err
	}
	if err := manifest.validate(verifier.policy, record); err != nil {
		return err
	}

	sbomBytes, err := readVerificationFile(verifyContext, entry.SBOMPath, verifier.policy.limits.MaxSBOMBytes, CodeSBOMRequired, CodeSBOMInvalid)
	if err != nil {
		return err
	}
	if err := verifyDocumentRecord(sbomBytes, record, MediaTypeSBOM); err != nil {
		return err
	}
	document, err := decodeSPDX(sbomBytes, verifier.policy.limits.MaxJSONDepth)
	if err != nil {
		return err
	}
	if err := validateSPDX(verifyContext, document, manifest, verifier.policy.limits); err != nil {
		return err
	}
	if err := verifier.provenance.VerifyProvenance(verifyContext, entry, manifest); err != nil {
		if verifyContext.Err() != nil {
			return contextError(verifyContext, err)
		}
		var safe *Error
		if errors.As(err, &safe) {
			return err
		}
		return imageError(CodeVerificationFailed, "The image provenance verifier rejected the staged artifact.", "Do not launch the image; pull an artifact from the approved repository and release workflow.", err)
	}
	return nil
}

func verifyDocumentRecord(data []byte, record cacheRecord, mediaType string) error {
	fileRecord, ok := cacheFileByMediaType(record, mediaType)
	if !ok || fileRecord.SourceSizeBytes != int64(len(data)) || fileRecord.InstalledSizeBytes != int64(len(data)) ||
		fileRecord.SourceDigest != fileRecord.InstalledDigest {
		return imageError(CodeDigestMismatch, "A verification document does not match its cache record.", "Do not launch the image; pull the complete artifact again by immutable digest.", nil)
	}
	hash := sha256.Sum256(data)
	actual := "sha256:" + hex.EncodeToString(hash[:])
	if actual != fileRecord.SourceDigest {
		return imageError(CodeDigestMismatch, "A verification document failed its recorded SHA-256 identity.", "Do not launch the image; pull the complete artifact again by immutable digest.", nil)
	}
	return nil
}
