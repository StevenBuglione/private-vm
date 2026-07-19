package image

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	virtualca "github.com/sigstore/sigstore-go/pkg/testing/ca"
	"google.golang.org/protobuf/encoding/protojson"
)

type signedStatementOptions struct {
	repository    string
	workflow      string
	ref           string
	commit        string
	digest        string
	subjectName   string
	statementType string
	predicateType string
	buildType     string
	builder       string
	repositoryID  string
	ownerID       string
	invocationID  string
}

func validSignedStatementOptions(manifest Manifest) signedStatementOptions {
	return signedStatementOptions{
		repository:    "https://github.com/" + officialRepository,
		workflow:      "/" + officialWorkflow,
		ref:           manifest.SourceRef,
		commit:        manifest.SourceCommit,
		digest:        stringsTrimSHA256(manifest.ImageDigest),
		subjectName:   officialSubjectName,
		statementType: inTotoStatementV1,
		predicateType: slsaProvenanceV1,
		buildType:     githubWorkflowBuildType,
		builder:       githubHostedRunnerBuilder,
		repositoryID:  officialRepositoryID,
		ownerID:       officialRepositoryOwnerID,
		invocationID:  "https://github.com/" + officialRepository + "/actions/runs/123456/attempts/1",
	}
}

func signedStatementBytes(t *testing.T, options signedStatementOptions) []byte {
	t.Helper()
	statement := provenanceStatement{
		Type:          options.statementType,
		Subject:       []provenanceSubject{{Name: options.subjectName, Digest: &provenanceDigest{SHA256: options.digest}}},
		PredicateType: options.predicateType,
		Predicate: &githubPredicate{
			BuildDefinition: &githubBuildDefinition{
				BuildType: options.buildType,
				ExternalParameters: &githubExternalParameters{Workflow: &githubWorkflowParameters{
					Ref: options.ref, Repository: options.repository, Path: options.workflow,
				}},
				InternalParameters: &githubInternalParameters{GitHub: &githubInternalIdentity{
					EventName: "push", RepositoryID: options.repositoryID, RepositoryOwnerID: options.ownerID,
				}},
				ResolvedDependencies: []githubResolvedDependency{{
					URI:    "git+" + options.repository + "@" + options.ref,
					Digest: &gitDependencyDigest{GitCommit: options.commit},
				}},
			},
			RunDetails: &githubRunDetails{
				Builder:  &githubBuilder{ID: options.builder},
				Metadata: &githubMetadata{InvocationID: options.invocationID},
			},
		},
	}
	return marshalJSON(t, statement)
}

func testSigstoreBundle(t *testing.T, deployment *virtualca.VirtualSigstore, payload []byte, san, issuer string, integratedTime time.Time) []byte {
	t.Helper()
	entity, err := deployment.AttestAtTime(san, issuer, payload, integratedTime, true)
	if err != nil {
		t.Fatal(err)
	}
	verificationContent, err := entity.VerificationContent()
	if err != nil {
		t.Fatal(err)
	}
	signatureContent, err := entity.SignatureContent()
	if err != nil {
		t.Fatal(err)
	}
	envelope := signatureContent.EnvelopeContent().RawEnvelope()
	payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	protoSignatures := make([]*protodsse.Signature, 0, len(envelope.Signatures))
	for _, signature := range envelope.Signatures {
		signatureBytes, err := base64.StdEncoding.DecodeString(signature.Sig)
		if err != nil {
			t.Fatal(err)
		}
		protoSignatures = append(protoSignatures, &protodsse.Signature{Sig: signatureBytes, Keyid: signature.KeyID})
	}
	tlogEntries, err := entity.TlogEntries()
	if err != nil {
		t.Fatal(err)
	}
	timestamps, err := entity.Timestamps()
	if err != nil {
		t.Fatal(err)
	}
	protoTimestamps := make([]*protocommon.RFC3161SignedTimestamp, 0, len(timestamps))
	for _, timestamp := range timestamps {
		protoTimestamps = append(protoTimestamps, &protocommon.RFC3161SignedTimestamp{SignedTimestamp: timestamp})
	}
	value := &protobundle.Bundle{
		MediaType: sigstoreBundleV03,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content:                   &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: verificationContent.Certificate().Raw}},
			TimestampVerificationData: &protobundle.TimestampVerificationData{Rfc3161Timestamps: protoTimestamps},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload: payloadBytes, PayloadType: envelope.PayloadType, Signatures: protoSignatures,
		}},
	}
	for _, entry := range tlogEntries {
		protoEntry := entry.TransparencyLogEntry()
		if protoEntry.KindVersion == nil {
			protoEntry.KindVersion = &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"}
		}
		value.VerificationMaterial.TlogEntries = append(value.VerificationMaterial.TlogEntries, protoEntry)
	}
	data, err := protojson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newVirtualDeployment(t *testing.T) *virtualca.VirtualSigstore {
	t.Helper()
	deployment, err := virtualca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	return deployment
}

func newVirtualProvenanceVerifier(t *testing.T, deployment *virtualca.VirtualSigstore, limits VerificationLimits) *sigstoreProvenanceVerifier {
	t.Helper()
	verifier, err := newSigstoreProvenanceVerifier(deployment, limits, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func validVirtualProvenance(t *testing.T, deployment *virtualca.VirtualSigstore, manifest Manifest) []byte {
	t.Helper()
	return testSigstoreBundle(
		t,
		deployment,
		signedStatementBytes(t, validSignedStatementOptions(manifest)),
		officialWorkflowIdentity(manifest),
		officialOIDCIssuer,
		time.Now().Add(time.Minute),
	)
}

func (fixture *verificationFixture) rewriteProvenance(t *testing.T, data []byte) {
	t.Helper()
	writeFixtureFile(t, fixture.entry.ProvenancePath, data)
	fixture.replaceFileRecord(MediaTypeProvenance, fileRecord("provenance.json", MediaTypeProvenance, data))
	fixture.writeRecord(t)
}

func TestSigstoreProvenanceAcceptsExactOfflineBundle(t *testing.T) {
	fixture := newVerificationFixture(t)
	deployment := newVirtualDeployment(t)
	bundleData := validVirtualProvenance(t, deployment, fixture.manifest)
	fixture.rewriteProvenance(t, bundleData)
	verifier := newVirtualProvenanceVerifier(t, deployment, fixture.policy.Limits)
	if err := verifier.VerifyProvenance(context.Background(), fixture.entry, fixture.manifest); err != nil {
		t.Fatalf("exact offline provenance failed: %v", err)
	}
}

func TestSignedProvenanceIdentityAndPredicateMismatchesFail(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*signedStatementOptions)
		san    func(Manifest) string
		issuer string
	}{
		{name: "repository", mutate: func(value *signedStatementOptions) { value.repository = "https://github.com/attacker/private-vm" }},
		{name: "workflow", mutate: func(value *signedStatementOptions) { value.workflow = "/.github/workflows/other.yml" }},
		{name: "ref", mutate: func(value *signedStatementOptions) { value.ref = "refs/tags/v9.9.9" }},
		{name: "unapproved tag", mutate: func(value *signedStatementOptions) { value.ref = "refs/tags/latest" }},
		{name: "commit", mutate: func(value *signedStatementOptions) { value.commit = strings.Repeat("c", 40) }},
		{name: "repository ID", mutate: func(value *signedStatementOptions) { value.repositoryID = "999999999" }},
		{name: "repository owner ID", mutate: func(value *signedStatementOptions) { value.ownerID = "999999999" }},
		{name: "digest", mutate: func(value *signedStatementOptions) { value.digest = strings.Repeat("d", 64) }},
		{name: "SLSA type", mutate: func(value *signedStatementOptions) { value.predicateType = "https://slsa.dev/provenance/v0.2" }},
		{name: "SAN", san: func(Manifest) string {
			return "https://github.com/attacker/private-vm/.github/workflows/release.yml@refs/tags/v1.0.0"
		}},
		{name: "issuer", issuer: "https://example.invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			deployment := newVirtualDeployment(t)
			options := validSignedStatementOptions(fixture.manifest)
			if test.mutate != nil {
				test.mutate(&options)
			}
			san := officialWorkflowIdentity(fixture.manifest)
			if test.san != nil {
				san = test.san(fixture.manifest)
			}
			issuer := officialOIDCIssuer
			if test.issuer != "" {
				issuer = test.issuer
			}
			fixture.rewriteProvenance(t, testSigstoreBundle(t, deployment, signedStatementBytes(t, options), san, issuer, time.Now().Add(time.Minute)))
			err := newVirtualProvenanceVerifier(t, deployment, fixture.policy.Limits).VerifyProvenance(context.Background(), fixture.entry, fixture.manifest)
			if err == nil {
				t.Fatal("mismatched signed provenance was accepted")
			}
			var safe *Error
			if !errors.As(err, &safe) {
				t.Fatalf("unclassified provenance error: %T", err)
			}
		})
	}
}

func TestSignedProvenanceRejectsSameUnapprovedManifestTag(t *testing.T) {
	for _, ref := range []string{"refs/heads/main", "refs/tags/latest", "refs/tags/v01.2.3", "refs/tags/v1.2.3-beta.1", "refs/tags/v1.2.3+build"} {
		t.Run(ref, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			fixture.manifest.SourceRef = ref
			deployment := newVirtualDeployment(t)
			fixture.rewriteProvenance(t, testSigstoreBundle(
				t,
				deployment,
				signedStatementBytes(t, validSignedStatementOptions(fixture.manifest)),
				officialWorkflowIdentity(fixture.manifest),
				officialOIDCIssuer,
				time.Now().Add(time.Minute),
			))
			err := newVirtualProvenanceVerifier(t, deployment, fixture.policy.Limits).VerifyProvenance(context.Background(), fixture.entry, fixture.manifest)
			assertImageErrorCode(t, err, CodeProvenanceIdentity)
		})
	}
}

func TestOfficialCertificateIdentityPinsRepositoryIDsAndInvocation(t *testing.T) {
	fixture := newVerificationFixture(t)
	verifier := &sigstoreProvenanceVerifier{enforceCertificateExtensions: true}
	invocationID := "https://github.com/" + officialRepository + "/actions/runs/123456/attempts/1"
	identity, err := verifier.certificateIdentity(fixture.manifest, invocationID)
	if err != nil {
		t.Fatal(err)
	}
	if identity.SourceRepositoryIdentifier != officialRepositoryID ||
		identity.SourceRepositoryOwnerIdentifier != officialRepositoryOwnerID ||
		identity.RunInvocationURI != invocationID {
		t.Fatalf("official certificate identity omitted immutable numeric IDs or invocation binding: %+v", identity.Extensions)
	}
	summary := fulciocert.Summary{
		SubjectAlternativeName: officialWorkflowIdentity(fixture.manifest),
		Extensions:             identity.Extensions,
	}
	summary.Issuer = officialOIDCIssuer
	if err := identity.Verify(summary); err != nil {
		t.Fatalf("exact official certificate identity failed: %v", err)
	}
	summary.RunInvocationURI = "https://github.com/" + officialRepository + "/actions/runs/999999/attempts/1"
	if err := identity.Verify(summary); err == nil {
		t.Fatal("certificate invocation different from the signed predicate was accepted")
	}
	summary.RunInvocationURI = invocationID
	summary.SourceRepositoryIdentifier = "999999999"
	if err := identity.Verify(summary); err == nil {
		t.Fatal("repository-name reuse with a different numeric ID was accepted")
	}
}

func TestProvenanceBundleMissingMalformedOversizeAndProofFailures(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		if err := os.Remove(fixture.entry.ProvenancePath); err != nil {
			t.Fatal(err)
		}
		deployment := newVirtualDeployment(t)
		err := newVirtualProvenanceVerifier(t, deployment, fixture.policy.Limits).VerifyProvenance(context.Background(), fixture.entry, fixture.manifest)
		assertImageErrorCode(t, err, CodeProvenanceRequired)
	})
	for _, test := range []struct {
		name string
		data func(*testing.T, *verificationFixture, *virtualca.VirtualSigstore) []byte
		code ErrorCode
	}{
		{name: "malformed", data: func(_ *testing.T, _ *verificationFixture, _ *virtualca.VirtualSigstore) []byte {
			return []byte(`{"mediaType":`)
		}, code: CodeProvenanceInvalid},
		{name: "duplicate", data: func(t *testing.T, fixture *verificationFixture, deployment *virtualca.VirtualSigstore) []byte {
			data := validVirtualProvenance(t, deployment, fixture.manifest)
			return []byte(strings.Replace(string(data), `"mediaType":`, `"mediaType":"`+sigstoreBundleV03+`","mediaType":`, 1))
		}, code: CodeProvenanceInvalid},
		{name: "unknown", data: func(t *testing.T, fixture *verificationFixture, deployment *virtualca.VirtualSigstore) []byte {
			data := validVirtualProvenance(t, deployment, fixture.manifest)
			return []byte(strings.Replace(string(data), `{`, `{"unknown":true,`, 1))
		}, code: CodeProvenanceInvalid},
		{name: "missing proof", data: func(t *testing.T, fixture *verificationFixture, deployment *virtualca.VirtualSigstore) []byte {
			data := validVirtualProvenance(t, deployment, fixture.manifest)
			var value protobundle.Bundle
			if err := protojson.Unmarshal(data, &value); err != nil {
				t.Fatal(err)
			}
			value.VerificationMaterial.TlogEntries[0].InclusionProof = nil
			encoded, err := protojson.Marshal(&value)
			if err != nil {
				t.Fatal(err)
			}
			return encoded
		}, code: CodeProvenanceInvalid},
		{name: "wrong Rekor profile", data: func(t *testing.T, fixture *verificationFixture, deployment *virtualca.VirtualSigstore) []byte {
			data := validVirtualProvenance(t, deployment, fixture.manifest)
			var value protobundle.Bundle
			if err := protojson.Unmarshal(data, &value); err != nil {
				t.Fatal(err)
			}
			value.VerificationMaterial.TlogEntries[0].KindVersion = &protorekor.KindVersion{Kind: "intoto", Version: "0.0.2"}
			encoded, err := protojson.Marshal(&value)
			if err != nil {
				t.Fatal(err)
			}
			return encoded
		}, code: CodeProvenanceInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			deployment := newVirtualDeployment(t)
			fixture.rewriteProvenance(t, test.data(t, fixture, deployment))
			err := newVirtualProvenanceVerifier(t, deployment, fixture.policy.Limits).VerifyProvenance(context.Background(), fixture.entry, fixture.manifest)
			assertImageErrorCode(t, err, test.code)
		})
	}
	t.Run("oversize", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		deployment := newVirtualDeployment(t)
		fixture.rewriteProvenance(t, validVirtualProvenance(t, deployment, fixture.manifest))
		limits := fixture.policy.Limits
		limits.MaxProvenanceBytes = 1
		err := newVirtualProvenanceVerifier(t, deployment, limits).VerifyProvenance(context.Background(), fixture.entry, fixture.manifest)
		assertImageErrorCode(t, err, CodeArtifactLimit)
	})
}

func TestProvenanceRejectsUntrustedAndExpiredCryptographicMaterial(t *testing.T) {
	for _, test := range []struct {
		name           string
		integratedTime time.Time
		untrusted      bool
	}{
		{name: "untrusted", integratedTime: time.Now().Add(time.Minute), untrusted: true},
		{name: "expired certificate", integratedTime: time.Now().Add(20 * time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			signer := newVirtualDeployment(t)
			bundle := testSigstoreBundle(t, signer, signedStatementBytes(t, validSignedStatementOptions(fixture.manifest)), officialWorkflowIdentity(fixture.manifest), officialOIDCIssuer, test.integratedTime)
			fixture.rewriteProvenance(t, bundle)
			trusted := signer
			if test.untrusted {
				trusted = newVirtualDeployment(t)
			}
			err := newVirtualProvenanceVerifier(t, trusted, fixture.policy.Limits).VerifyProvenance(context.Background(), fixture.entry, fixture.manifest)
			assertImageErrorCode(t, err, CodeProvenanceInvalid)
		})
	}
}

func TestProvenanceCancellationTimeoutAndOfflineReverification(t *testing.T) {
	fixture := newVerificationFixture(t)
	deployment := newVirtualDeployment(t)
	fixture.rewriteProvenance(t, validVirtualProvenance(t, deployment, fixture.manifest))
	verifier := newVirtualProvenanceVerifier(t, deployment, fixture.policy.Limits)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	assertImageErrorCode(t, verifier.VerifyProvenance(cancelled, fixture.entry, fixture.manifest), CodePullCancelled)
	timedOut, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	assertImageErrorCode(t, verifier.VerifyProvenance(timedOut, fixture.entry, fixture.manifest), CodePullTimeout)

	originalTransport := http.DefaultTransport
	trap := &countingRoundTripper{}
	http.DefaultTransport = trap
	defer func() { http.DefaultTransport = originalTransport }()
	for range 2 {
		if err := verifier.VerifyProvenance(context.Background(), fixture.entry, fixture.manifest); err != nil {
			t.Fatalf("offline cache reverification failed: %v", err)
		}
	}
	if trap.calls.Load() != 0 {
		t.Fatalf("offline verification attempted %d network requests", trap.calls.Load())
	}
}

type countingRoundTripper struct{ calls atomic.Int64 }

func (transport *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return nil, errors.New("network is forbidden during provenance verification")
}
