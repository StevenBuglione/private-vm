package image

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	DocumentDescribes []string           `json:"documentDescribes"`
	Packages          []spdxPackage      `json:"packages"`
	Files             []spdxFile         `json:"files"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string          `json:"SPDXID"`
	Name             string          `json:"name"`
	VersionInfo      string          `json:"versionInfo"`
	DownloadLocation string          `json:"downloadLocation"`
	FilesAnalyzed    *bool           `json:"filesAnalyzed"`
	Checksums        *[]spdxChecksum `json:"checksums"`
}

type spdxFile struct {
	SPDXID    string         `json:"SPDXID"`
	FileName  string         `json:"fileName"`
	FileTypes []string       `json:"fileTypes"`
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

var spdxDocumentFields = []string{
	"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace",
	"creationInfo", "documentDescribes", "packages", "files", "relationships",
}

func decodeSPDX(data []byte, maximumDepth int) (spdxDocument, error) {
	var document spdxDocument
	if err := decodeClosedJSON(data, maximumDepth, spdxDocumentFields, &document); err != nil {
		return spdxDocument{}, imageError(
			CodeSBOMInvalid,
			"The SPDX SBOM is not a closed private-vm SPDX 2.3 document.",
			"Publish the documented bounded SPDX 2.3 image-closure profile with every required field exactly once.",
			err,
		)
	}
	return document, nil
}

func validateSPDX(ctx context.Context, document spdxDocument, manifest Manifest, limits VerificationLimits) error {
	artifact := manifestArtifactName(manifest)
	expectedNamespace := "https://private-vm.dev/spdx/images/" + artifact + "/" + strings.TrimPrefix(manifest.ImageDigest, "sha256:")
	if document.SPDXVersion != "SPDX-2.3" || document.DataLicense != "CC0-1.0" ||
		document.SPDXID != "SPDXRef-DOCUMENT" || document.Name != artifact ||
		document.DocumentNamespace != expectedNamespace ||
		document.CreationInfo.Created != manifest.BuiltAt ||
		!slices.Equal(document.CreationInfo.Creators, []string{"Tool: private-vm release workflow"}) ||
		!slices.Equal(document.DocumentDescribes, []string{imageSPDXID}) {
		return sbomInvalid("The SPDX document identity or creation record does not bind the published image manifest.")
	}
	if len(document.Packages) < 2 || len(document.Packages) > limits.MaxPackages ||
		len(document.Files) != 1 || len(document.Files) > limits.MaxFiles ||
		len(document.Relationships) < 3 || len(document.Relationships) > limits.MaxRelationships {
		return imageError(CodeArtifactLimit, "The SPDX package, file or relationship count is outside the image-closure bounds.", "Publish one bounded image file, the image package, its Nix closure packages and their required relationships.", nil)
	}

	identifiers := map[string]string{"SPDXRef-DOCUMENT": "document"}
	closureIDs := make([]string, 0, len(document.Packages)-1)
	closurePaths := make(map[string]struct{}, len(document.Packages)-1)
	previousClosurePath := ""
	imagePackageFound := false
	for index, pkg := range document.Packages {
		if index%128 == 0 {
			if err := ctx.Err(); err != nil {
				return contextError(ctx, err)
			}
		}
		if !spdxIDPattern.MatchString(pkg.SPDXID) || !boundedText(pkg.Name, 1, 256) ||
			!boundedText(pkg.VersionInfo, 1, 128) || pkg.FilesAnalyzed == nil {
			return sbomInvalid("An SPDX package entry is missing a bounded required identity field.")
		}
		storeHash, storeName := "", ""
		if pkg.SPDXID != imageSPDXID {
			var ok bool
			storeHash, storeName, ok = parseNixStoreURI(pkg.DownloadLocation)
			if !ok {
				return sbomInvalid("An SPDX closure package does not identify a canonical Nix store path.")
			}
			if _, duplicate := closurePaths[pkg.DownloadLocation]; duplicate {
				return sbomInvalid("The SPDX closure contains a duplicate Nix store identity.")
			}
			if previousClosurePath != "" && pkg.DownloadLocation <= previousClosurePath {
				return sbomInvalid("The SPDX closure packages are not in canonical Nix store path order.")
			}
			closurePaths[pkg.DownloadLocation] = struct{}{}
			previousClosurePath = pkg.DownloadLocation
		}
		if _, duplicate := identifiers[pkg.SPDXID]; duplicate {
			return sbomInvalid("The SPDX document contains a duplicate element identifier.")
		}
		identifiers[pkg.SPDXID] = "package"
		if pkg.SPDXID == imageSPDXID {
			if index != 0 || imagePackageFound || pkg.Name != artifact || pkg.VersionInfo != manifest.NixOSVersion ||
				pkg.DownloadLocation != "NOASSERTION" || !*pkg.FilesAnalyzed ||
				pkg.Checksums == nil || !exactSHA256(*pkg.Checksums, manifest.UncompressedSHA256) {
				return sbomInvalid("The SPDX image package does not bind the installed QCOW2 and NixOS release.")
			}
			imagePackageFound = true
			continue
		}
		if *pkg.FilesAnalyzed || pkg.Checksums == nil || len(*pkg.Checksums) != 0 ||
			pkg.SPDXID != "SPDXRef-Package-"+storeHash || pkg.Name != storeName ||
			(pkg.VersionInfo != "NOASSERTION" && (!versionInfoPattern.MatchString(pkg.VersionInfo) || !strings.Contains(storeName, pkg.VersionInfo))) {
			return sbomInvalid("An SPDX closure package is not a bounded files-unanalysed Nix store identity.")
		}
		closureIDs = append(closureIDs, pkg.SPDXID)
	}
	if !imagePackageFound || len(closureIDs) == 0 {
		return sbomInvalid("The SPDX document is missing the image package or its Nix closure package set.")
	}
	file := document.Files[0]
	if file.SPDXID != imageFileSPDXID || file.FileName != "./image.qcow2" ||
		!slices.Equal(file.FileTypes, []string{"BINARY"}) ||
		!exactSHA256(file.Checksums, manifest.UncompressedSHA256) {
		return sbomInvalid("The SPDX file entry does not bind the installed QCOW2 bytes.")
	}
	if _, duplicate := identifiers[file.SPDXID]; duplicate {
		return sbomInvalid("The SPDX document contains a duplicate package/file identifier.")
	}
	identifiers[file.SPDXID] = "file"

	expectedRelationships := []string{
		relationshipKey("SPDXRef-DOCUMENT", "DESCRIBES", imageSPDXID),
		relationshipKey(imageSPDXID, "CONTAINS", imageFileSPDXID),
	}
	for _, identifier := range closureIDs {
		expectedRelationships = append(expectedRelationships, relationshipKey(imageSPDXID, "DEPENDS_ON", identifier))
	}
	if len(document.Relationships) != len(expectedRelationships) {
		return sbomInvalid("The SPDX relationship graph does not cover the exact image closure.")
	}
	for index, relationship := range document.Relationships {
		if index%128 == 0 {
			if err := ctx.Err(); err != nil {
				return contextError(ctx, err)
			}
		}
		if _, ok := identifiers[relationship.SPDXElementID]; !ok {
			return sbomInvalid("An SPDX relationship references an unknown source element.")
		}
		if _, ok := identifiers[relationship.RelatedSPDXElement]; !ok {
			return sbomInvalid("An SPDX relationship references an unknown related element.")
		}
		key := relationshipKey(relationship.SPDXElementID, relationship.RelationshipType, relationship.RelatedSPDXElement)
		if key != expectedRelationships[index] {
			return sbomInvalid("The SPDX relationship graph is not the exact canonical image-closure graph.")
		}
	}
	return nil
}

func manifestArtifactName(manifest Manifest) string {
	if manifest.Bundle != nil {
		return "private-vm-" + manifest.Role + "-" + *manifest.Bundle + "-image"
	}
	return "private-vm-" + manifest.Role + "-image"
}

func exactSHA256(checksums []spdxChecksum, expected string) bool {
	return len(checksums) == 1 && checksums[0].Algorithm == "SHA256" &&
		checksums[0].ChecksumValue == expected && validHex(expected, 32)
}

func parseNixStoreURI(value string) (string, string, bool) {
	if !nixStorePathPattern.MatchString(value) {
		return "", "", false
	}
	base := strings.TrimPrefix(value, "file:///nix/store/")
	if len(base) < 34 || base[32] != '-' {
		return "", "", false
	}
	return base[:32], base[33:], true
}

func boundedText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func relationshipKey(left, relationship, right string) string {
	return fmt.Sprintf("%s\x00%s\x00%s", left, relationship, right)
}

func sbomInvalid(message string) error {
	return imageError(
		CodeSBOMInvalid,
		message,
		"Publish a complete bounded SPDX 2.3 image-closure document that exactly identifies the installed image.",
		nil,
	)
}
