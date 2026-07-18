package image

import "testing"

func TestManifestTrustPolicy(t *testing.T) {
	h64 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	h40 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	m := Manifest{
		SchemaVersion: 1, Project: "private-vm", Role: "workstation",
		Architecture: "x86_64", SourceRepository: "StevenBuglione/private-vm",
		SourceCommit: h40, Workflow: ".github/workflows/release.yml",
		ImageDigest: "sha256:" + h64, UncompressedSHA256: h64,
		GuestAPIMajor: 1, SBOMDigest: "sha256:" + h64,
	}
	p := TrustPolicy{
		Repository:   "StevenBuglione/private-vm",
		Workflow:     ".github/workflows/release.yml",
		Architecture: "x86_64", Role: "workstation", APIMajor: 1,
	}
	if err := m.Validate(p); err != nil {
		t.Fatal(err)
	}
	m.SourceRepository = "attacker/fork"
	if err := m.Validate(p); err == nil {
		t.Fatal("expected repository mismatch")
	}
}
