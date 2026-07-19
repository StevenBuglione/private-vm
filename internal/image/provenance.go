package image

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sigbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigverify "github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	sigstoreBundleV03         = "application/vnd.dev.sigstore.bundle.v0.3+json"
	maximumCertificateBytes   = 64 << 10
	maximumSignatureBytes     = 16 << 10
	maximumCheckpointBytes    = 64 << 10
	maximumCanonicalBodyBytes = 1 << 20
)

// Embedded from sigstore/sigstore-go v1.2.2 commit
// 55aa6240784677449a564e66a0fca7a6a3605ecd. The source, SHA-256 and reviewed
// update procedure are recorded in docs/30-sources.md.
//
//go:embed trust/sigstore-public-good-trusted-root-v1.2.2.json
var embeddedPublicGoodTrustedRoot []byte

type sigstoreProvenanceVerifier struct {
	limits                       VerificationLimits
	verifier                     *sigverify.Verifier
	enforceCertificateExtensions bool
}

func newEmbeddedOfficialProvenanceVerifier(limits VerificationLimits) (provenanceVerifier, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(embeddedPublicGoodTrustedRoot)
	if err != nil {
		return nil, imageError(
			CodeVerificationMissing,
			"The embedded Sigstore public-good trust root is unavailable.",
			"Install a reviewed private-vm build containing the pinned public-good trust snapshot.",
			err,
		)
	}
	return newSigstoreProvenanceVerifier(trustedRoot, limits, true, true)
}

// newSigstoreProvenanceVerifier is package-private so focused tests can use a
// generated trust deployment without creating an official-policy bypass.
func newSigstoreProvenanceVerifier(material root.TrustedMaterial, limits VerificationLimits, requireSCT, enforceExtensions bool) (*sigstoreProvenanceVerifier, error) {
	if material == nil {
		return nil, imageError(CodeVerificationMissing, "No Sigstore trusted material is available.", "Install the reviewed embedded public-good trust snapshot.", nil)
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	options := []sigverify.VerifierOption{
		sigverify.WithTransparencyLog(1),
		sigverify.WithObserverTimestamps(1),
	}
	if requireSCT {
		options = append(options, sigverify.WithSignedCertificateTimestamps(1))
	}
	verifier, err := sigverify.NewVerifier(material, options...)
	if err != nil {
		return nil, provenanceInvalid("The offline Sigstore verifier could not be initialized.", err)
	}
	return &sigstoreProvenanceVerifier{
		limits: limits, verifier: verifier,
		enforceCertificateExtensions: enforceExtensions,
	}, nil
}

func (verifier *sigstoreProvenanceVerifier) VerifyProvenance(ctx context.Context, entry Entry, manifest Manifest) error {
	if verifier == nil || verifier.verifier == nil {
		return imageError(CodeVerificationMissing, "The offline Sigstore provenance verifier is unavailable.", "Install a reviewed private-vm build containing IMG-003.", nil)
	}
	if err := ctx.Err(); err != nil {
		return contextError(ctx, err)
	}
	record, err := readCacheRecord(entry.RecordPath)
	if err != nil {
		return err
	}
	if err := validateProvenanceCacheBindings(manifest, record); err != nil {
		return err
	}
	bundleBytes, err := readVerificationFile(ctx, entry.ProvenancePath, verifier.limits.MaxProvenanceBytes, CodeProvenanceRequired, CodeProvenanceInvalid)
	if err != nil {
		return err
	}
	if err := verifyDocumentRecord(bundleBytes, record, MediaTypeProvenance); err != nil {
		return err
	}
	return verifier.verifyBundle(ctx, bundleBytes, manifest)
}

func (verifier *sigstoreProvenanceVerifier) verifyBundle(ctx context.Context, bundleBytes []byte, manifest Manifest) error {
	if err := ctx.Err(); err != nil {
		return contextError(ctx, err)
	}
	entity, payload, err := decodeSigstoreBundle(bundleBytes, verifier.limits)
	if err != nil {
		return err
	}
	statement, err := decodeProvenanceStatement(payload, verifier.limits.MaxJSONDepth)
	if err != nil {
		return err
	}
	invocationID, err := statement.invocationIDForPolicy()
	if err != nil {
		return err
	}
	digestBytes, err := hex.DecodeString(stringsTrimSHA256(manifest.ImageDigest))
	if err != nil || len(digestBytes) != 32 {
		return imageError(CodeDigestMismatch, "The compressed image digest cannot be bound to provenance.", "Do not launch the image; publish one canonical SHA-256 image digest.", err)
	}
	identity, err := verifier.certificateIdentity(manifest, invocationID)
	if err != nil {
		return provenanceInvalid("The exact official certificate identity policy could not be constructed.", err)
	}
	result, err := verifier.verifier.Verify(
		entity,
		sigverify.NewPolicy(
			sigverify.WithArtifactDigest("sha256", digestBytes),
			sigverify.WithCertificateIdentity(identity),
		),
	)
	if err != nil {
		if ctx.Err() != nil {
			return contextError(ctx, err)
		}
		return provenanceInvalid("The Sigstore signature, certificate, transparency proof, observer time or compressed-image digest is invalid.", err)
	}
	if err := ctx.Err(); err != nil {
		return contextError(ctx, err)
	}
	if result == nil || result.Signature == nil || result.Signature.Certificate == nil || result.VerifiedIdentity == nil {
		return provenanceInvalid("Sigstore verification did not return the required certificate identity.", nil)
	}
	if !hasVerifiedObserver(result) {
		return provenanceInvalid("Sigstore verification did not return the required authenticated observer timestamp.", nil)
	}
	if err := statement.validate(ctx, manifest); err != nil {
		return err
	}
	return nil
}

func (verifier *sigstoreProvenanceVerifier) certificateIdentity(manifest Manifest, invocationID string) (sigverify.CertificateIdentity, error) {
	san := officialWorkflowIdentity(manifest)
	sanMatcher, err := sigverify.NewSANMatcher(san, "")
	if err != nil {
		return sigverify.CertificateIdentity{}, err
	}
	issuerMatcher, err := sigverify.NewIssuerMatcher(officialOIDCIssuer, "")
	if err != nil {
		return sigverify.CertificateIdentity{}, err
	}
	extensions := fulciocert.Extensions{}
	if verifier.enforceCertificateExtensions {
		repositoryURL := "https://github.com/" + officialRepository
		extensions = fulciocert.Extensions{
			GithubWorkflowTrigger:               "push",
			GithubWorkflowSHA:                   manifest.SourceCommit,
			GithubWorkflowName:                  "Release",
			GithubWorkflowRepository:            officialRepository,
			GithubWorkflowRef:                   manifest.SourceRef,
			BuildSignerURI:                      san,
			BuildSignerDigest:                   manifest.SourceCommit,
			RunnerEnvironment:                   "github-hosted",
			SourceRepositoryURI:                 repositoryURL,
			SourceRepositoryDigest:              manifest.SourceCommit,
			SourceRepositoryRef:                 manifest.SourceRef,
			SourceRepositoryIdentifier:          officialRepositoryID,
			SourceRepositoryOwnerURI:            "https://github.com/StevenBuglione",
			SourceRepositoryOwnerIdentifier:     officialRepositoryOwnerID,
			BuildConfigURI:                      san,
			BuildConfigDigest:                   manifest.SourceCommit,
			BuildTrigger:                        "push",
			RunInvocationURI:                    invocationID,
			SourceRepositoryVisibilityAtSigning: "public",
		}
	}
	return sigverify.NewCertificateIdentity(sanMatcher, issuerMatcher, extensions)
}

func decodeSigstoreBundle(data []byte, limits VerificationLimits) (*sigbundle.Bundle, []byte, error) {
	if len(data) == 0 {
		return nil, nil, imageError(CodeProvenanceRequired, "The official image has no Sigstore provenance bundle.", "Pull a complete official artifact containing its offline bundle.", nil)
	}
	if err := rejectDuplicateJSONKeys(data, limits.MaxJSONDepth); err != nil {
		return nil, nil, provenanceInvalid("The Sigstore bundle contains duplicate, malformed, trailing or over-depth JSON.", err)
	}
	protobufBundle := new(protobundle.Bundle)
	unmarshal := protojson.UnmarshalOptions{DiscardUnknown: false, RecursionLimit: limits.MaxJSONDepth}
	if err := unmarshal.Unmarshal(data, protobufBundle); err != nil {
		return nil, nil, provenanceInvalid("The Sigstore bundle is not valid closed protobuf JSON.", err)
	}
	canonical, err := protojson.MarshalOptions{}.Marshal(protobufBundle)
	if err != nil || !sameJSONValue(data, canonical) {
		return nil, nil, provenanceInvalid("The Sigstore bundle uses aliases, unknown/default fields or noncanonical protobuf JSON values.", err)
	}
	if err := validateSigstoreBundleShape(protobufBundle, limits); err != nil {
		return nil, nil, err
	}
	entity, err := sigbundle.NewBundle(protobufBundle)
	if err != nil {
		return nil, nil, provenanceInvalid("The Sigstore bundle failed its structural inclusion-proof validation.", err)
	}
	return entity, protobufBundle.GetDsseEnvelope().GetPayload(), nil
}

func validateSigstoreBundleShape(value *protobundle.Bundle, limits VerificationLimits) error {
	if value.GetMediaType() != sigstoreBundleV03 || value.GetDsseEnvelope() == nil || value.GetMessageSignature() != nil || value.GetVerificationMaterial() == nil {
		return provenanceInvalid("The provenance layer is not one Sigstore bundle v0.3 DSSE attestation.", nil)
	}
	envelope := value.GetDsseEnvelope()
	if envelope.GetPayloadType() != sigbundle.IntotoMediaType || len(envelope.GetPayload()) < 2 ||
		int64(len(envelope.GetPayload())) > limits.MaxProvenancePayloadBytes || len(envelope.GetSignatures()) != 1 ||
		len(envelope.GetSignatures()[0].GetSig()) < 1 || len(envelope.GetSignatures()[0].GetSig()) > maximumSignatureBytes ||
		len(envelope.GetSignatures()[0].GetKeyid()) != 0 {
		return provenanceInvalid("The Sigstore DSSE envelope is missing or outside its exact payload/signature bounds.", nil)
	}
	material := value.GetVerificationMaterial()
	certificate := material.GetCertificate()
	if certificate == nil || material.GetPublicKey() != nil || material.GetX509CertificateChain() != nil ||
		len(certificate.GetRawBytes()) < 1 || len(certificate.GetRawBytes()) > maximumCertificateBytes || len(material.GetTlogEntries()) != 1 {
		return provenanceInvalid("The Sigstore verification material is not one bounded Fulcio certificate and Rekor entry.", nil)
	}
	if timestamps := material.GetTimestampVerificationData().GetRfc3161Timestamps(); len(timestamps) > 1 ||
		(len(timestamps) == 1 && (len(timestamps[0].GetSignedTimestamp()) < 1 || len(timestamps[0].GetSignedTimestamp()) > maximumCertificateBytes)) {
		return provenanceInvalid("The Sigstore timestamp material exceeds the official bundle profile.", nil)
	}
	entry := material.GetTlogEntries()[0]
	proof := entry.GetInclusionProof()
	if entry.GetLogIndex() < 0 || entry.GetIntegratedTime() < 1 || entry.GetLogId() == nil || len(entry.GetLogId().GetKeyId()) != 32 ||
		entry.GetKindVersion() == nil || entry.GetKindVersion().GetKind() != "dsse" || entry.GetKindVersion().GetVersion() != "0.0.1" ||
		len(entry.GetCanonicalizedBody()) < 2 || len(entry.GetCanonicalizedBody()) > maximumCanonicalBodyBytes || proof == nil ||
		proof.GetLogIndex() != entry.GetLogIndex() || proof.GetTreeSize() < 1 || len(proof.GetRootHash()) != 32 ||
		len(proof.GetHashes()) > limits.MaxTransparencyProofHashes || proof.GetCheckpoint() == nil ||
		len(proof.GetCheckpoint().GetEnvelope()) < 1 || len(proof.GetCheckpoint().GetEnvelope()) > maximumCheckpointBytes {
		return provenanceInvalid("The Rekor entry or inclusion proof is missing or outside its exact bounds.", nil)
	}
	for _, hash := range proof.GetHashes() {
		if len(hash) != 32 {
			return provenanceInvalid("A Rekor inclusion-proof hash is not SHA-256 sized.", nil)
		}
	}
	if promise := entry.GetInclusionPromise(); promise != nil && len(promise.GetSignedEntryTimestamp()) > maximumSignatureBytes {
		return provenanceInvalid("The Rekor inclusion promise exceeds its bound.", nil)
	}
	return nil
}

func validateProvenanceCacheBindings(manifest Manifest, record cacheRecord) error {
	imageRecord, imageOK := cacheFileByMediaType(record, MediaTypeQCOW2Zstd)
	provenanceRecord, provenanceOK := cacheFileByMediaType(record, MediaTypeProvenance)
	if !imageOK || imageRecord.SourceDigest != manifest.ImageDigest || imageRecord.SourceSizeBytes != manifest.CompressedSizeBytes {
		return imageError(CodeDigestMismatch, "The attested compressed image identity does not match the immutable cache descriptor.", "Do not launch the image; pull the complete artifact again by immutable digest.", nil)
	}
	if !provenanceOK || provenanceRecord.SourceDigest != provenanceRecord.InstalledDigest ||
		provenanceRecord.SourceSizeBytes != provenanceRecord.InstalledSizeBytes {
		return imageError(CodeDigestMismatch, "The provenance layer identity does not match its immutable cache record.", "Do not launch the image; pull the complete artifact again by immutable digest.", nil)
	}
	return nil
}

func hasVerifiedObserver(result *sigverify.VerificationResult) bool {
	for _, timestamp := range result.VerifiedTimestamps {
		if (timestamp.Type == "Tlog" || timestamp.Type == "TimestampAuthority") && !timestamp.Timestamp.IsZero() {
			return true
		}
	}
	return false
}

func sameJSONValue(left, right []byte) bool {
	decode := func(data []byte) (any, error) {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return nil, errors.New("trailing JSON document")
		}
		return value, nil
	}
	leftValue, leftErr := decode(left)
	rightValue, rightErr := decode(right)
	return leftErr == nil && rightErr == nil && reflect.DeepEqual(leftValue, rightValue)
}

func stringsTrimSHA256(value string) string {
	const prefix = "sha256:"
	if len(value) >= len(prefix) && value[:len(prefix)] == prefix {
		return value[len(prefix):]
	}
	return value
}

func provenanceInvalid(message string, cause error) error {
	return imageError(
		CodeProvenanceInvalid,
		message,
		"Do not launch the image; use a bounded offline Sigstore bundle from the official protected release workflow.",
		cause,
	)
}
