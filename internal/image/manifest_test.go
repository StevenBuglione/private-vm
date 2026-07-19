package image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type verificationFixture struct {
	entry    Entry
	manifest Manifest
	sbom     spdxDocument
	record   cacheRecord
	policy   CompatibilityPolicy
}

func newVerificationFixture(t *testing.T) *verificationFixture {
	t.Helper()
	directory := t.TempDir()
	bundle := "development"
	imageBytes := []byte("QFI\xfbprivate-vm-installed-image")
	compressedBytes := []byte("bounded-compressed-image-fixture")
	imageHash := sha256Hex(imageBytes)
	compressedDigest := digestString(compressedBytes)
	manifest := Manifest{
		SchemaVersion: manifestSchemaVersion, Project: "private-vm", Role: "workstation", Bundle: &bundle,
		Architecture: "x86_64", SourceRepository: "StevenBuglione/private-vm",
		SourceCommit: strings.Repeat("b", 40), SourceRef: "refs/tags/v1.0.0-rc.1",
		Workflow: ".github/workflows/release.yml", ImageDigest: compressedDigest,
		UncompressedSHA256: imageHash, CompressedSizeBytes: int64(len(compressedBytes)),
		UncompressedSizeBytes: int64(len(imageBytes)), VirtualSizeBytes: 80 << 30,
		NixOSVersion: frozenNixOSVersion, FlakeLockSHA256: strings.Repeat("a", 64),
		GuestAPIMajor: 1, GuestAPIMinor: 0, MinimumQEMUVersion: frozenQEMUMinimum,
		Capabilities: slices.Clone(roleCapabilities["workstation"]), BuiltAt: "2026-07-19T12:00:00Z",
	}
	sbom := validSPDXDocument(manifest)
	sbomBytes := marshalJSON(t, sbom)
	manifest.SBOMDigest = digestString(sbomBytes)
	manifestBytes := marshalJSON(t, manifest)
	provenanceBytes := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json"}`)

	record := cacheRecord{
		SchemaVersion:     1,
		OCIManifestDigest: "sha256:" + strings.Repeat("1", 64),
		Files: []cacheFileRecord{
			{Name: "image.qcow2", MediaType: MediaTypeQCOW2Zstd, SourceDigest: compressedDigest, InstalledDigest: "sha256:" + imageHash, SourceSizeBytes: int64(len(compressedBytes)), InstalledSizeBytes: int64(len(imageBytes))},
			fileRecord("manifest.json", MediaTypeManifest, manifestBytes),
			fileRecord("sbom.spdx.json", MediaTypeSBOM, sbomBytes),
			fileRecord("provenance.json", MediaTypeProvenance, provenanceBytes),
		},
	}
	entry := entryFor(directory, record.OCIManifestDigest)
	writeFixtureFile(t, entry.ImagePath, imageBytes)
	writeFixtureFile(t, entry.ManifestPath, manifestBytes)
	writeFixtureFile(t, entry.SBOMPath, sbomBytes)
	writeFixtureFile(t, entry.ProvenancePath, provenanceBytes)
	writeFixtureFile(t, entry.RecordPath, marshalJSON(t, record))
	return &verificationFixture{
		entry: entry, manifest: manifest, sbom: sbom, record: record,
		policy: CompatibilityPolicy{
			Role: "workstation", Bundle: bundle, HostArchitecture: "amd64",
			GuestAPIMajor: 1, GuestAPIMinor: 0, MinimumGuestAPIMinor: 0,
			HostQEMUVersion: "10.2.4", NixOSVersion: frozenNixOSVersion,
			Limits: DefaultVerificationLimits(),
		},
	}
}

func validSPDXDocument(manifest Manifest) spdxDocument {
	imageFilesAnalyzed, closureFilesAnalyzed := true, false
	imageChecksums := []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: manifest.UncompressedSHA256}}
	closureChecksums := []spdxChecksum{}
	artifact := manifestArtifactName(manifest)
	closureID := "SPDXRef-Package-0123456789abcdfghijklmnpqrsvwxyz"
	return spdxDocument{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		Name:              artifact,
		DocumentNamespace: "https://private-vm.dev/spdx/images/" + artifact + "/" + strings.TrimPrefix(manifest.ImageDigest, "sha256:"),
		CreationInfo:      spdxCreationInfo{Created: manifest.BuiltAt, Creators: []string{"Tool: private-vm release workflow"}},
		DocumentDescribes: []string{imageSPDXID},
		Packages: []spdxPackage{
			{SPDXID: imageSPDXID, Name: artifact, VersionInfo: manifest.NixOSVersion, DownloadLocation: "NOASSERTION", FilesAnalyzed: &imageFilesAnalyzed, Checksums: &imageChecksums},
			{SPDXID: closureID, Name: "nixos-system-private-vm-workstation-26.05", VersionInfo: "26.05", DownloadLocation: "file:///nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-private-vm-workstation-26.05", FilesAnalyzed: &closureFilesAnalyzed, Checksums: &closureChecksums},
		},
		Files: []spdxFile{{SPDXID: imageFileSPDXID, FileName: "./image.qcow2", FileTypes: []string{"BINARY"}, Checksums: []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: manifest.UncompressedSHA256}}}},
		Relationships: []spdxRelationship{
			{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: imageSPDXID},
			{SPDXElementID: imageSPDXID, RelationshipType: "CONTAINS", RelatedSPDXElement: imageFileSPDXID},
			{SPDXElementID: imageSPDXID, RelationshipType: "DEPENDS_ON", RelatedSPDXElement: closureID},
		},
	}
}

func TestOfficialVerifierAcceptsExactManifestSBOMAndProvenance(t *testing.T) {
	fixture := newVerificationFixture(t)
	called := false
	verifier, err := NewOfficialVerifier(fixture.policy, ProvenanceVerificationFunc(func(_ context.Context, entry Entry, manifest Manifest) error {
		called = true
		if entry.ManifestDigest != fixture.entry.ManifestDigest || manifest.SourceCommit != fixture.manifest.SourceCommit {
			t.Fatal("provenance seam received the wrong verified identity")
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), fixture.entry); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("complete verification bypassed the mandatory provenance seam")
	}
}

func TestOfficialVerifierComposesBehindOCIPuller(t *testing.T) {
	for _, test := range []struct {
		name      string
		wrongRole bool
		wantCode  ErrorCode
	}{
		{name: "verified publication"},
		{name: "compatibility blocks publication", wrongRole: true, wantCode: CodeRoleMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			artifact := newArtifactFixture(t)
			bundle := "development"
			imageDescriptor := artifact.descriptors[MediaTypeQCOW2Zstd]
			manifest := Manifest{
				SchemaVersion: 1, Project: "private-vm", Role: "workstation", Bundle: &bundle,
				Architecture: "x86_64", SourceRepository: "StevenBuglione/private-vm",
				SourceCommit: strings.Repeat("b", 40), SourceRef: "refs/tags/v1.0.0-rc.1",
				Workflow: ".github/workflows/release.yml", ImageDigest: imageDescriptor.Digest.String(),
				UncompressedSHA256: sha256Hex(artifact.image), CompressedSizeBytes: imageDescriptor.Size,
				UncompressedSizeBytes: int64(len(artifact.image)), VirtualSizeBytes: 80 << 30,
				NixOSVersion: frozenNixOSVersion, FlakeLockSHA256: strings.Repeat("a", 64),
				GuestAPIMajor: 1, GuestAPIMinor: 0, MinimumQEMUVersion: frozenQEMUMinimum,
				Capabilities: slices.Clone(roleCapabilities["workstation"]), BuiltAt: "2026-07-19T12:00:00Z",
			}
			sbomBytes := marshalJSON(t, validSPDXDocument(manifest))
			sbomDescriptor := replaceOCIComponent(t, &artifact, MediaTypeSBOM, "sbom.spdx.json", sbomBytes)
			manifest.SBOMDigest = sbomDescriptor.Digest.String()
			if test.wrongRole {
				manifest.Role = "scanner"
			}
			replaceOCIComponent(t, &artifact, MediaTypeManifest, "manifest.json", marshalJSON(t, manifest))

			policy := CompatibilityPolicy{
				Role: "workstation", Bundle: bundle, HostArchitecture: "amd64",
				GuestAPIMajor: 1, GuestAPIMinor: 0, MinimumGuestAPIMinor: 0,
				HostQEMUVersion: "10.2.4", NixOSVersion: frozenNixOSVersion,
				Limits: DefaultVerificationLimits(),
			}
			verifier, err := NewOfficialVerifier(policy, ProvenanceVerificationFunc(acceptingProvenance))
			if err != nil {
				t.Fatal(err)
			}
			puller, cache := newTestPuller(t, artifact, verifier, nil)
			entry, err := puller.Pull(context.Background(), "registry.example/repo/image:stable")
			if test.wantCode != "" {
				assertImageErrorCode(t, err, test.wantCode)
				assertNoPartial(t, cache)
				if _, statErr := os.Lstat(digestPath(cache.root, artifact.repository.manifest.Digest.String())); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("rejected artifact became runnable: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(entry.ImagePath); err != nil {
				t.Fatalf("verified cache entry was not published: %v", err)
			}
		})
	}
}

func TestManifestGoAndJSONSchemaFieldsRemainIdentical(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", "image-manifest.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	typeOfManifest := reflect.TypeFor[Manifest]()
	goFields := make([]string, 0, typeOfManifest.NumField())
	for index := range typeOfManifest.NumField() {
		goFields = append(goFields, typeOfManifest.Field(index).Tag.Get("json"))
	}
	slices.Sort(goFields)
	schemaFields := make([]string, 0, len(schema.Properties))
	for field := range schema.Properties {
		schemaFields = append(schemaFields, field)
	}
	slices.Sort(schemaFields)
	required := slices.Clone(schema.Required)
	slices.Sort(required)
	if !slices.Equal(goFields, schemaFields) || !slices.Equal(goFields, required) {
		t.Fatalf("manifest contract drift: go=%v schema=%v required=%v", goFields, schemaFields, required)
	}
}

func TestOfficialVerifierRequiresIMG003(t *testing.T) {
	fixture := newVerificationFixture(t)
	_, err := NewOfficialVerifier(fixture.policy, nil)
	assertImageErrorCode(t, err, CodeVerificationMissing)
	var typedNil ProvenanceVerificationFunc
	_, err = NewOfficialVerifier(fixture.policy, typedNil)
	assertImageErrorCode(t, err, CodeVerificationMissing)
}

func TestManifestCompatibilityAndCacheBindingsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
		code   ErrorCode
	}{
		{name: "role", mutate: func(value *Manifest) { value.Role = "scanner" }, code: CodeRoleMismatch},
		{name: "bundle", mutate: func(value *Manifest) { bundle := "basic"; value.Bundle = &bundle }, code: CodeBundleMismatch},
		{name: "architecture", mutate: func(value *Manifest) { value.Architecture = "aarch64" }, code: CodeArchitectureMismatch},
		{name: "API major", mutate: func(value *Manifest) { value.GuestAPIMajor = 2 }, code: CodeGuestAPIMismatch},
		{name: "API minor newer", mutate: func(value *Manifest) { value.GuestAPIMinor = 1 }, code: CodeGuestAPIMismatch},
		{name: "QEMU lower than frozen", mutate: func(value *Manifest) { value.MinimumQEMUVersion = "9.1" }, code: CodeQEMUVersionMismatch},
		{name: "QEMU noncanonical", mutate: func(value *Manifest) { value.MinimumQEMUVersion = "09.2" }, code: CodeQEMUVersionMismatch},
		{name: "capability missing", mutate: func(value *Manifest) { value.Capabilities = value.Capabilities[:len(value.Capabilities)-1] }, code: CodeCapabilityMismatch},
		{name: "capability extra", mutate: func(value *Manifest) { value.Capabilities = append(value.Capabilities, "unexpected") }, code: CodeCapabilityMismatch},
		{name: "capability duplicate", mutate: func(value *Manifest) {
			value.Capabilities = append(value.Capabilities, value.Capabilities[len(value.Capabilities)-1])
		}, code: CodeCapabilityMismatch},
		{name: "capability unsorted", mutate: func(value *Manifest) {
			value.Capabilities[0], value.Capabilities[1] = value.Capabilities[1], value.Capabilities[0]
		}, code: CodeCapabilityMismatch},
		{name: "compressed digest", mutate: func(value *Manifest) { value.ImageDigest = "sha256:" + strings.Repeat("2", 64) }, code: CodeDigestMismatch},
		{name: "compressed size", mutate: func(value *Manifest) { value.CompressedSizeBytes++ }, code: CodeDigestMismatch},
		{name: "installed digest", mutate: func(value *Manifest) { value.UncompressedSHA256 = strings.Repeat("2", 64) }, code: CodeDigestMismatch},
		{name: "installed size", mutate: func(value *Manifest) { value.UncompressedSizeBytes++ }, code: CodeDigestMismatch},
		{name: "SBOM digest", mutate: func(value *Manifest) { value.SBOMDigest = "sha256:" + strings.Repeat("2", 64) }, code: CodeDigestMismatch},
		{name: "flake lock", mutate: func(value *Manifest) { value.FlakeLockSHA256 = "not-a-hash" }, code: CodeManifestContract},
		{name: "NixOS version", mutate: func(value *Manifest) { value.NixOSVersion = "unstable" }, code: CodeManifestContract},
		{name: "source commit", mutate: func(value *Manifest) { value.SourceCommit = "unknown" }, code: CodeManifestContract},
		{name: "source ref", mutate: func(value *Manifest) { value.SourceRef = "refs/tags/../unsafe" }, code: CodeManifestContract},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			test.mutate(&fixture.manifest)
			fixture.rewriteManifest(t)
			called := false
			verifier := fixture.verifier(t, func(context.Context, Entry, Manifest) error { called = true; return nil })
			err := verifier.Verify(context.Background(), fixture.entry)
			assertImageErrorCode(t, err, test.code)
			if called {
				t.Fatal("invalid manifest reached provenance verification")
			}
		})
	}
}

func TestNonWorkstationBundleMustBeExplicitNull(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.policy.Role = "scanner"
	fixture.policy.Bundle = ""
	fixture.manifest.Role = "scanner"
	fixture.manifest.Bundle = nil
	fixture.manifest.Capabilities = slices.Clone(roleCapabilities["scanner"])
	fixture.sbom = validSPDXDocument(fixture.manifest)
	fixture.rewriteSBOM(t)
	if err := fixture.verifier(t, acceptingProvenance).Verify(context.Background(), fixture.entry); err != nil {
		t.Fatalf("scanner manifest with explicit null bundle failed: %v", err)
	}

	emptyBundle := ""
	fixture.manifest.Bundle = &emptyBundle
	fixture.rewriteManifest(t)
	err := fixture.verifier(t, acceptingProvenance).Verify(context.Background(), fixture.entry)
	assertImageErrorCode(t, err, CodeBundleMismatch)
}

func TestGuestAPIMinorCompatibilityHonorsBothBounds(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.policy.GuestAPIMinor = 2
	fixture.policy.MinimumGuestAPIMinor = 1
	err := fixture.verifier(t, acceptingProvenance).Verify(context.Background(), fixture.entry)
	assertImageErrorCode(t, err, CodeGuestAPIMismatch)
}

func TestManifestJSONIsClosedPresenceAwareAndDuplicateSafe(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "unknown", mutate: func(data []byte) []byte {
			return bytes.Replace(data, []byte(`{"schema_version":`), []byte(`{"unknown":true,"schema_version":`), 1)
		}},
		{name: "duplicate", mutate: func(data []byte) []byte {
			return bytes.Replace(data, []byte(`"project":"private-vm"`), []byte(`"project":"private-vm","project":"private-vm"`), 1)
		}},
		{name: "trailing", mutate: func(data []byte) []byte { return append(data, []byte(` {}`)...) }},
		{name: "missing", mutate: func(data []byte) []byte {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, "source_ref")
			return marshalJSON(t, fields)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			data := test.mutate(marshalJSON(t, fixture.manifest))
			fixture.rewriteRawManifest(t, data)
			err := fixture.verifier(t, acceptingProvenance).Verify(context.Background(), fixture.entry)
			assertImageErrorCode(t, err, CodeManifestContract)
		})
	}
}

func TestSPDXStrictProfileAndBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*spdxDocument)
		code   ErrorCode
	}{
		{name: "wrong version", mutate: func(value *spdxDocument) { value.SPDXVersion = "SPDX-2.2" }, code: CodeSBOMInvalid},
		{name: "wrong license", mutate: func(value *spdxDocument) { value.DataLicense = "NOASSERTION" }, code: CodeSBOMInvalid},
		{name: "wrong document ID", mutate: func(value *spdxDocument) { value.SPDXID = "SPDXRef-OTHER" }, code: CodeSBOMInvalid},
		{name: "wrong namespace", mutate: func(value *spdxDocument) { value.DocumentNamespace += "-other" }, code: CodeSBOMInvalid},
		{name: "wrong creation", mutate: func(value *spdxDocument) { value.CreationInfo.Created = "2026-07-19T13:00:00Z" }, code: CodeSBOMInvalid},
		{name: "missing closure", mutate: func(value *spdxDocument) {
			value.Packages = value.Packages[:1]
			value.Relationships = value.Relationships[:2]
		}, code: CodeArtifactLimit},
		{name: "duplicate package", mutate: func(value *spdxDocument) { value.Packages[1].SPDXID = imageSPDXID }, code: CodeSBOMInvalid},
		{name: "non Nix closure", mutate: func(value *spdxDocument) { value.Packages[1].DownloadLocation = "https://example.invalid/package" }, code: CodeSBOMInvalid},
		{name: "closure ID not store hash", mutate: func(value *spdxDocument) {
			value.Packages[1].SPDXID = "SPDXRef-Package-11111111111111111111111111111111"
		}, code: CodeSBOMInvalid},
		{name: "closure name not store basename", mutate: func(value *spdxDocument) { value.Packages[1].Name = "alias" }, code: CodeSBOMInvalid},
		{name: "closure version absent from store name", mutate: func(value *spdxDocument) { value.Packages[1].VersionInfo = "99.99" }, code: CodeSBOMInvalid},
		{name: "image package checksum", mutate: func(value *spdxDocument) { (*value.Packages[0].Checksums)[0].ChecksumValue = strings.Repeat("2", 64) }, code: CodeSBOMInvalid},
		{name: "closure checksums missing", mutate: func(value *spdxDocument) { value.Packages[1].Checksums = nil }, code: CodeSBOMInvalid},
		{name: "image file checksum", mutate: func(value *spdxDocument) { value.Files[0].Checksums[0].ChecksumValue = strings.Repeat("2", 64) }, code: CodeSBOMInvalid},
		{name: "duplicate relationship", mutate: func(value *spdxDocument) { value.Relationships[2] = value.Relationships[1] }, code: CodeSBOMInvalid},
		{name: "unknown relationship element", mutate: func(value *spdxDocument) { value.Relationships[2].RelatedSPDXElement = "SPDXRef-MISSING" }, code: CodeSBOMInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			test.mutate(&fixture.sbom)
			fixture.rewriteSBOM(t)
			err := fixture.verifier(t, acceptingProvenance).Verify(context.Background(), fixture.entry)
			assertImageErrorCode(t, err, test.code)
		})
	}
}

func TestSPDXRejectsMissingAndNullNestedRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "missing creation creator", mutate: func(root map[string]any) { delete(jsonObject(root["creationInfo"]), "creators") }},
		{name: "null creation creator", mutate: func(root map[string]any) { jsonObject(root["creationInfo"])["creators"] = nil }},
		{name: "missing package files analyzed", mutate: func(root map[string]any) { delete(jsonObject(jsonArray(root["packages"])[1]), "filesAnalyzed") }},
		{name: "null package files analyzed", mutate: func(root map[string]any) { jsonObject(jsonArray(root["packages"])[1])["filesAnalyzed"] = nil }},
		{name: "missing closure checksums", mutate: func(root map[string]any) { delete(jsonObject(jsonArray(root["packages"])[1]), "checksums") }},
		{name: "null closure checksums", mutate: func(root map[string]any) { jsonObject(jsonArray(root["packages"])[1])["checksums"] = nil }},
		{name: "missing file checksum algorithm", mutate: func(root map[string]any) {
			delete(jsonObject(jsonArray(jsonObject(jsonArray(root["files"])[0])["checksums"])[0]), "algorithm")
		}},
		{name: "null file checksum algorithm", mutate: func(root map[string]any) {
			jsonObject(jsonArray(jsonObject(jsonArray(root["files"])[0])["checksums"])[0])["algorithm"] = nil
		}},
		{name: "missing relationship type", mutate: func(root map[string]any) { delete(jsonObject(jsonArray(root["relationships"])[0]), "relationshipType") }},
		{name: "null relationship type", mutate: func(root map[string]any) { jsonObject(jsonArray(root["relationships"])[0])["relationshipType"] = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			var root map[string]any
			if err := json.Unmarshal(marshalJSON(t, fixture.sbom), &root); err != nil {
				t.Fatal(err)
			}
			test.mutate(root)
			fixture.rewriteRawSBOM(t, marshalJSON(t, root))
			err := fixture.verifier(t, acceptingProvenance).Verify(context.Background(), fixture.entry)
			assertImageErrorCode(t, err, CodeSBOMInvalid)
		})
	}
}

func TestSPDXRejectsDuplicateAndNoncanonicalClosurePaths(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*spdxDocument)
	}{
		{
			name: "duplicate store path",
			mutate: func(document *spdxDocument) {
				duplicate := document.Packages[1]
				duplicate.SPDXID = "SPDXRef-Package-11111111111111111111111111111111"
				document.Packages = append(document.Packages, duplicate)
				document.Relationships = append(document.Relationships, spdxRelationship{SPDXElementID: imageSPDXID, RelationshipType: "DEPENDS_ON", RelatedSPDXElement: duplicate.SPDXID})
			},
		},
		{
			name: "unsorted store paths",
			mutate: func(document *spdxDocument) {
				filesAnalyzed := false
				checksums := []spdxChecksum{}
				earlier := spdxPackage{
					SPDXID: "SPDXRef-Package-00000000000000000000000000000000", Name: "earlier-1.0", VersionInfo: "1.0",
					DownloadLocation: "file:///nix/store/00000000000000000000000000000000-earlier-1.0", FilesAnalyzed: &filesAnalyzed, Checksums: &checksums,
				}
				document.Packages = append(document.Packages, earlier)
				document.Relationships = append(document.Relationships, spdxRelationship{SPDXElementID: imageSPDXID, RelationshipType: "DEPENDS_ON", RelatedSPDXElement: earlier.SPDXID})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			test.mutate(&fixture.sbom)
			fixture.rewriteSBOM(t)
			err := fixture.verifier(t, acceptingProvenance).Verify(context.Background(), fixture.entry)
			assertImageErrorCode(t, err, CodeSBOMInvalid)
		})
	}
}

func TestSPDXJSONRejectsUnknownDuplicateTrailingAndMalformed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "unknown nested", mutate: func(data []byte) []byte {
			return bytes.Replace(data, []byte(`"versionInfo":"26.05"`), []byte(`"versionInfo":"26.05","unknown":true`), 1)
		}},
		{name: "duplicate nested", mutate: func(data []byte) []byte {
			return bytes.Replace(data, []byte(`"relationshipType":"DESCRIBES"`), []byte(`"relationshipType":"DESCRIBES","relationshipType":"DESCRIBES"`), 1)
		}},
		{name: "trailing", mutate: func(data []byte) []byte { return append(data, []byte(` []`)...) }},
		{name: "malformed", mutate: func(data []byte) []byte { return data[:len(data)/2] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			data := test.mutate(marshalJSON(t, fixture.sbom))
			fixture.rewriteRawSBOM(t, data)
			err := fixture.verifier(t, acceptingProvenance).Verify(context.Background(), fixture.entry)
			assertImageErrorCode(t, err, CodeSBOMInvalid)
		})
	}
}

func TestOfficialStrictModeRequiresSBOM(t *testing.T) {
	fixture := newVerificationFixture(t)
	if err := os.Remove(fixture.entry.SBOMPath); err != nil {
		t.Fatal(err)
	}
	err := fixture.verifier(t, acceptingProvenance).Verify(context.Background(), fixture.entry)
	assertImageErrorCode(t, err, CodeSBOMRequired)
}

func TestVerificationCancellationTimeoutAndLimits(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := fixture.verifier(t, acceptingProvenance).Verify(ctx, fixture.entry)
		assertImageErrorCode(t, err, CodePullCancelled)
	})
	t.Run("timeout", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		fixture.policy.Limits.Timeout = time.Millisecond
		verifier := fixture.verifier(t, func(ctx context.Context, _ Entry, _ Manifest) error { <-ctx.Done(); return ctx.Err() })
		err := verifier.Verify(context.Background(), fixture.entry)
		assertImageErrorCode(t, err, CodePullTimeout)
	})
	for _, test := range []struct {
		name string
		set  func(*VerificationLimits)
	}{
		{name: "manifest bytes", set: func(limits *VerificationLimits) { limits.MaxManifestBytes = 1 }},
		{name: "SBOM bytes", set: func(limits *VerificationLimits) { limits.MaxSBOMBytes = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture(t)
			test.set(&fixture.policy.Limits)
			err := fixture.verifier(t, acceptingProvenance).Verify(context.Background(), fixture.entry)
			assertImageErrorCode(t, err, CodeArtifactLimit)
		})
	}
}

func TestArchitectureMappingAndPolicySnapshot(t *testing.T) {
	for host, imageArchitecture := range map[string]string{"amd64": "x86_64", "arm64": "aarch64"} {
		mapped, ok := mapHostArchitecture(host)
		if !ok || mapped != imageArchitecture {
			t.Fatalf("mapping %s=%s,%v", host, mapped, ok)
		}
	}
	fixture := newVerificationFixture(t)
	verifier, err := NewOfficialVerifier(fixture.policy, ProvenanceVerificationFunc(acceptingProvenance))
	if err != nil {
		t.Fatal(err)
	}
	fixture.policy.Role = "scanner"
	fixture.policy.Limits.MaxManifestBytes = 1
	if err := verifier.Verify(context.Background(), fixture.entry); err != nil {
		t.Fatalf("caller mutation changed immutable verifier policy: %v", err)
	}
}

func TestProvenanceFailureIsRedactedAndStable(t *testing.T) {
	fixture := newVerificationFixture(t)
	privateCause := errors.New("provenance-private-marker")
	err := fixture.verifier(t, func(context.Context, Entry, Manifest) error { return privateCause }).Verify(context.Background(), fixture.entry)
	assertImageErrorCode(t, err, CodeVerificationFailed)
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if strings.Contains(formatError(format, err), "provenance-private-marker") {
			t.Fatalf("format %s exposed provenance cause", format)
		}
	}
	if !errors.Is(err, privateCause) {
		t.Fatal("trusted errors.Is lost provenance cause")
	}
}

func (fixture *verificationFixture) verifier(t *testing.T, provenance ProvenanceVerificationFunc) Verifier {
	t.Helper()
	verifier, err := NewOfficialVerifier(fixture.policy, provenance)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func (fixture *verificationFixture) rewriteManifest(t *testing.T) {
	t.Helper()
	fixture.rewriteRawManifest(t, marshalJSON(t, fixture.manifest))
}

func (fixture *verificationFixture) rewriteRawManifest(t *testing.T, data []byte) {
	t.Helper()
	writeFixtureFile(t, fixture.entry.ManifestPath, data)
	fixture.replaceFileRecord(MediaTypeManifest, fileRecord("manifest.json", MediaTypeManifest, data))
	fixture.writeRecord(t)
}

func (fixture *verificationFixture) rewriteSBOM(t *testing.T) {
	t.Helper()
	fixture.rewriteRawSBOM(t, marshalJSON(t, fixture.sbom))
}

func (fixture *verificationFixture) rewriteRawSBOM(t *testing.T, data []byte) {
	t.Helper()
	writeFixtureFile(t, fixture.entry.SBOMPath, data)
	fixture.replaceFileRecord(MediaTypeSBOM, fileRecord("sbom.spdx.json", MediaTypeSBOM, data))
	fixture.manifest.SBOMDigest = digestString(data)
	fixture.rewriteManifest(t)
}

func (fixture *verificationFixture) replaceFileRecord(mediaType string, replacement cacheFileRecord) {
	for index := range fixture.record.Files {
		if fixture.record.Files[index].MediaType == mediaType {
			fixture.record.Files[index] = replacement
			return
		}
	}
}

func (fixture *verificationFixture) writeRecord(t *testing.T) {
	t.Helper()
	writeFixtureFile(t, fixture.entry.RecordPath, marshalJSON(t, fixture.record))
}

func fileRecord(name, mediaType string, data []byte) cacheFileRecord {
	digest := digestString(data)
	return cacheFileRecord{Name: name, MediaType: mediaType, SourceDigest: digest, InstalledDigest: digest, SourceSizeBytes: int64(len(data)), InstalledSizeBytes: int64(len(data))}
}

func replaceOCIComponent(t *testing.T, fixture *artifactFixture, mediaType, title string, data []byte) ocispec.Descriptor {
	t.Helper()
	descriptor := descriptorFor(mediaType, data)
	descriptor.Annotations = map[string]string{ociTitleAnnotation: title}
	fixture.repository.blobs[descriptor.Digest.String()] = data
	fixture.descriptors[mediaType] = descriptor
	mutateManifest(t, fixture, func(manifest *ocispec.Manifest) {
		for index := range manifest.Layers {
			if manifest.Layers[index].MediaType == mediaType {
				manifest.Layers[index] = descriptor
				return
			}
		}
		t.Fatalf("fixture has no %s component", mediaType)
	})
	return descriptor
}

func writeFixtureFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func jsonObject(value any) map[string]any { return value.(map[string]any) }
func jsonArray(value any) []any           { return value.([]any) }

func digestString(data []byte) string { return "sha256:" + sha256Hex(data) }

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func acceptingProvenance(context.Context, Entry, Manifest) error { return nil }

func formatError(format string, err error) string {
	var buffer strings.Builder
	_, _ = fmt.Fprintf(&buffer, format, err)
	return buffer.String()
}
