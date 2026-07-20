// Package systeminstall implements the bounded generic-Linux installation
// transaction. It owns only the fixed package integration paths; session,
// image-cache, scratch, USB and user-export data are never installation inputs.
package systeminstall

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	SchemaVersion       = 1
	MaximumManifestSize = 1 << 20
	MaximumBundleFile   = 128 << 20
	MaximumBundleBytes  = 256 << 20
	InstalledManifest   = "/usr/share/private-vm/install-manifest.json"
)

// File is one immutable, allowlisted bundle-to-host mapping.
type File struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        uint32 `json:"mode"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	Preserve    bool   `json:"preserve"`
}

// Manifest is the closed generic archive and installed-record contract.
type Manifest struct {
	SchemaVersion int    `json:"schema_version"`
	Product       string `json:"product"`
	Version       string `json:"version"`
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	Files         []File `json:"files"`
}

type fileTemplate struct {
	source      string
	destination string
	mode        uint32
	preserve    bool
}

var fileTemplates = []fileTemplate{
	{"LICENSE", "/usr/share/doc/private-vm/LICENSE", 0o444, false},
	{"README.md", "/usr/share/doc/private-vm/README.md", 0o444, false},
	{"completions/bash/private-vm", "/usr/share/bash-completion/completions/private-vm", 0o444, false},
	{"completions/fish/private-vm.fish", "/usr/share/fish/vendor_completions.d/private-vm.fish", 0o444, false},
	{"completions/zsh/_private-vm", "/usr/share/zsh/site-functions/_private-vm", 0o444, false},
	{"config.toml", "/etc/private-vm/config.toml", 0o600, true},
	{"integration/90-private-vm.rules", "/usr/lib/udev/rules.d/90-private-vm.rules", 0o444, false},
	{"integration/90-private-vm.sysctl", "/usr/lib/sysctl.d/90-private-vm.conf", 0o444, false},
	{"integration/org.private-vm.policy", "/usr/share/polkit-1/actions/org.private-vm.policy", 0o444, false},
	{"integration/private-vm.conf.example", "/usr/share/private-vm/usbguard/private-vm.conf.example", 0o444, false},
	{"integration/private-vm.sysusers", "/usr/lib/sysusers.d/private-vm.conf", 0o444, false},
	{"integration/private-vm.tmpfiles", "/usr/lib/tmpfiles.d/private-vm.conf", 0o444, false},
	{"integration/private-vmd.service", "/usr/lib/systemd/system/private-vmd.service", 0o444, false},
	{"man/private-vm.1", "/usr/share/man/man1/private-vm.1", 0o444, false},
	{"man/private-vmd.8", "/usr/share/man/man8/private-vmd.8", 0o444, false},
	{"private-vm", "/usr/bin/private-vm", 0o755, false},
	{"private-vmd", "/usr/libexec/private-vmd", 0o755, false},
}

// BuildManifest hashes the exact generic archive tree. It is used only by the
// release builder; installation re-verifies every byte before any mutation.
func BuildManifest(ctx context.Context, root, version string) (Manifest, error) {
	if ctx == nil || !validVersion(version) {
		return Manifest{}, errors.New("invalid manifest build request")
	}
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Product:       "private-vm",
		Version:       version,
		OS:            "linux",
		Architecture:  "amd64",
		Files:         make([]File, 0, len(fileTemplates)),
	}
	var total int64
	for _, template := range fileTemplates {
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		size, digest, err := hashRegularFile(ctx, root, template.source, MaximumBundleFile)
		if err != nil {
			return Manifest{}, err
		}
		if size > MaximumBundleBytes-total {
			return Manifest{}, errors.New("bundle exceeds byte limit")
		}
		total += size
		manifest.Files = append(manifest.Files, File{
			Source: template.source, Destination: template.destination,
			Mode: template.mode, Size: size, SHA256: digest, Preserve: template.preserve,
		})
	}
	return manifest, nil
}

func MarshalManifest(manifest Manifest) ([]byte, error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil || len(encoded)+1 > MaximumManifestSize {
		return nil, errors.New("manifest encoding failed")
	}
	return append(encoded, '\n'), nil
}

func LoadManifest(root string) (Manifest, []byte, error) {
	return loadManifestFile(filepath.Join(root, "manifest.json"))
}

func loadManifestFile(path string) (Manifest, []byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > MaximumManifestSize {
		return Manifest{}, nil, errors.New("manifest is missing or unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > MaximumManifestSize {
		return Manifest{}, nil, errors.New("manifest could not be read")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Manifest{}, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, nil, errors.New("manifest is malformed")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return Manifest{}, nil, errors.New("manifest contains trailing data")
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, nil, err
	}
	return manifest, data, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaVersion || manifest.Product != "private-vm" ||
		manifest.OS != "linux" || manifest.Architecture != "amd64" || !validVersion(manifest.Version) ||
		len(manifest.Files) != len(fileTemplates) {
		return errors.New("manifest identity is invalid")
	}
	for index, template := range fileTemplates {
		file := manifest.Files[index]
		if file.Source != template.source || file.Destination != template.destination ||
			file.Mode != template.mode || file.Preserve != template.preserve || file.Size <= 0 ||
			file.Size > MaximumBundleFile || len(file.SHA256) != sha256.Size*2 {
			return errors.New("manifest file contract is invalid")
		}
		if _, err := hex.DecodeString(file.SHA256); err != nil || strings.ToLower(file.SHA256) != file.SHA256 {
			return errors.New("manifest file digest is invalid")
		}
	}
	return nil
}

func validVersion(version string) bool {
	if len(version) < 1 || len(version) > 64 || strings.TrimSpace(version) != version {
		return false
	}
	for _, char := range version {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') &&
			!(char >= '0' && char <= '9') && !strings.ContainsRune(".+-", char) {
			return false
		}
	}
	return true
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var stack []map[string]struct{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("manifest is malformed")
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, map[string]struct{}{})
			case '}':
				stack = stack[:len(stack)-1]
			}
		case string:
			if len(stack) == 0 {
				continue
			}
			// Decoder.Token does not identify keys directly. Peek at the next
			// non-space byte: a colon means this token is an object key.
			remaining := data[decoder.InputOffset():]
			reader := bufio.NewReader(bytes.NewReader(remaining))
			for {
				char, readErr := reader.ReadByte()
				if readErr != nil {
					break
				}
				if char == ' ' || char == '\t' || char == '\r' || char == '\n' {
					continue
				}
				if char == ':' {
					current := stack[len(stack)-1]
					if _, exists := current[value]; exists {
						return errors.New("manifest contains a duplicate field")
					}
					current[value] = struct{}{}
				}
				break
			}
		}
	}
}

func hashRegularFile(ctx context.Context, root, relative string, limit int64) (int64, string, error) {
	if root == "" || relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return 0, "", errors.New("bundle path is invalid")
	}
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := rejectSymlinkPath(root, path); err != nil {
		return 0, "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, "", errors.New("bundle file could not be opened")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return 0, "", errors.New("bundle file is not a bounded regular file")
	}
	hash := sha256.New()
	buffer := make([]byte, 1<<20)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			total += int64(count)
			if total > limit {
				return 0, "", errors.New("bundle file exceeded its byte limit")
			}
			_, _ = hash.Write(buffer[:count])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return 0, "", errors.New("bundle file could not be read")
		}
	}
	return total, fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func verifyBundle(ctx context.Context, root string, manifest Manifest) error {
	var total int64
	for _, expected := range manifest.Files {
		size, digest, err := hashRegularFile(ctx, root, expected.Source, MaximumBundleFile)
		if err != nil || size != expected.Size || digest != expected.SHA256 {
			return errors.New("bundle content verification failed")
		}
		if size > MaximumBundleBytes-total {
			return errors.New("bundle exceeds byte limit")
		}
		total += size
	}
	return nil
}

func rejectSymlinkPath(root, path string) error {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("path escapes bundle root")
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("bundle path contains a missing or symbolic component")
		}
	}
	return nil
}
