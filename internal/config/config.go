package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const (
	SchemaVersion       = 1
	DefaultSystemPath   = "/etc/private-vm/config.toml"
	DefaultRuntimePath  = "/run/private-vm"
	DefaultImageCache   = "/var/lib/private-vm/images"
	DefaultScratchPath  = "/var/lib/private-vm/scratch"
	OfficialRepository  = "StevenBuglione/private-vm"
	DefaultRegistry     = "ghcr.io"
	DefaultCleanupLimit = 30
)

type Config struct {
	SchemaVersion int         `toml:"schema_version" json:"schema_version"`
	Strict        bool        `toml:"strict" json:"strict"`
	ImageSource   ImageSource `toml:"image_source" json:"image_source"`
	Runtime       Runtime     `toml:"runtime" json:"runtime"`
	Desktop       Desktop     `toml:"desktop" json:"desktop"`
	VPN           VPN         `toml:"vpn" json:"vpn"`
	USB           USB         `toml:"usb" json:"usb"`
	Logging       Logging     `toml:"logging" json:"logging"`
}

type ImageSource struct {
	Registry           string `toml:"registry" json:"registry"`
	Repository         string `toml:"repository" json:"repository"`
	Channel            string `toml:"channel" json:"channel"`
	RequireAttestation bool   `toml:"require_attestation" json:"require_attestation"`
}

type Runtime struct {
	Directory             string `toml:"directory" json:"directory"`
	ImageCache            string `toml:"image_cache" json:"image_cache"`
	ScratchDirectory      string `toml:"scratch_directory" json:"scratch_directory"`
	SmallScratchMaxBytes  uint64 `toml:"small_scratch_max_bytes" json:"small_scratch_max_bytes"`
	CleanupTimeoutSeconds int    `toml:"cleanup_timeout_seconds" json:"cleanup_timeout_seconds"`
}

type Desktop struct {
	Bundle      string `toml:"bundle" json:"bundle"`
	Viewer      string `toml:"viewer" json:"viewer"`
	Audio       bool   `toml:"audio" json:"audio"`
	MemoryBytes uint64 `toml:"memory_bytes" json:"memory_bytes"`
	VCPUs       uint32 `toml:"vcpus" json:"vcpus"`
}

type VPN struct {
	ProfileName              string `toml:"profile_name" json:"profile_name"`
	DisableIPv6IfNotTunneled bool   `toml:"disable_ipv6_if_not_tunneled" json:"disable_ipv6_if_not_tunneled"`
}

type USB struct {
	RequireUSBGuard   bool   `toml:"require_usbguard" json:"require_usbguard"`
	DefaultFilesystem string `toml:"default_filesystem" json:"default_filesystem"`
}

type Logging struct {
	PersistentLifecycleMetadata bool `toml:"persistent_lifecycle_metadata" json:"persistent_lifecycle_metadata"`
	Telemetry                   bool `toml:"telemetry" json:"telemetry"`
}

func Defaults() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Strict:        true,
		ImageSource:   ImageSource{Registry: DefaultRegistry, Repository: OfficialRepository, Channel: "stable", RequireAttestation: true},
		Runtime:       Runtime{Directory: DefaultRuntimePath, ImageCache: DefaultImageCache, ScratchDirectory: DefaultScratchPath, SmallScratchMaxBytes: 16 << 30, CleanupTimeoutSeconds: DefaultCleanupLimit},
		Desktop:       Desktop{Bundle: "development", Viewer: "remote-viewer", MemoryBytes: 16 << 30, VCPUs: 8},
		VPN:           VPN{ProfileName: "proton-p2p", DisableIPv6IfNotTunneled: true},
		USB:           USB{RequireUSBGuard: true, DefaultFilesystem: "luks2-ext4"},
	}
}

// Load applies system, user, and explicit files in ascending precedence. A
// missing default file is ignored; a missing explicit file is an error.
func Load(explicitPath string) (Config, error) {
	cfg := Defaults()
	paths := []struct {
		path     string
		required bool
	}{{DefaultSystemPath, false}}
	userPath, err := UserPath()
	if err != nil {
		return Config{}, err
	}
	paths = append(paths, struct {
		path     string
		required bool
	}{userPath, false})
	if explicitPath != "" && explicitPath != userPath && explicitPath != DefaultSystemPath {
		paths = append(paths, struct {
			path     string
			required bool
		}{explicitPath, true})
	}
	for _, item := range paths {
		data, readErr := os.ReadFile(item.path)
		if errors.Is(readErr, os.ErrNotExist) && !item.required {
			continue
		}
		if readErr != nil {
			return Config{}, fmt.Errorf("read configuration %q: %w", item.path, readErr)
		}
		if err := decodeInto(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("configuration %q: %w", item.path, err)
		}
	}
	return cfg, cfg.Validate()
}

// LoadDaemon loads only the system/explicit daemon configuration. A privileged
// service must never inherit root's per-user configuration layer.
func LoadDaemon(path string) (Config, error) {
	if path == "" {
		path = DefaultSystemPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read daemon configuration %q: %w", path, err)
	}
	cfg := Defaults()
	if err := decodeInto(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("daemon configuration %q: %w", path, err)
	}
	return cfg, cfg.Validate()
}

func Decode(r io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if err != nil {
		return Config{}, err
	}
	if len(data) > 1<<20 {
		return Config{}, errors.New("configuration exceeds 1 MiB")
	}
	cfg := Defaults()
	if err := decodeInto(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, cfg.Validate()
}

func decodeInto(data []byte, cfg *Config) error {
	if err := rejectSecretKeys(data); err != nil {
		return err
	}
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return err
	}
	return nil
}

func rejectSecretKeys(data []byte) error {
	var value map[string]any
	if err := toml.Unmarshal(data, &value); err != nil {
		return err
	}
	var walk func(map[string]any) error
	walk = func(m map[string]any) error {
		for key, raw := range m {
			normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
			for _, forbidden := range []string{"private_key", "password", "passphrase", "secret", "token", "magnet"} {
				if strings.Contains(normalized, forbidden) {
					return fmt.Errorf("secret-bearing field %q is forbidden in configuration", key)
				}
			}
			if child, ok := raw.(map[string]any); ok {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value)
}

func UserPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("resolve user configuration directory: %w", err)
		}
		base = dir
	}
	return filepath.Join(base, "private-vm", "config.toml"), nil
}

func (c Config) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if c.ImageSource.Registry == "" || c.ImageSource.Repository == "" {
		return errors.New("image registry and repository are required")
	}
	if c.ImageSource.Repository == OfficialRepository && !c.ImageSource.RequireAttestation {
		return errors.New("official images always require attestation")
	}
	if c.ImageSource.Channel != "stable" && c.ImageSource.Channel != "edge" {
		return errors.New("image channel must be stable or edge")
	}
	for label, path := range map[string]string{"runtime directory": c.Runtime.Directory, "image cache": c.Runtime.ImageCache, "scratch directory": c.Runtime.ScratchDirectory} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("%s must be a clean absolute path", label)
		}
	}
	if c.Runtime.CleanupTimeoutSeconds < 5 || c.Runtime.CleanupTimeoutSeconds > 300 {
		return errors.New("cleanup timeout must be between 5 and 300 seconds")
	}
	if c.Desktop.VCPUs < 1 || c.Desktop.VCPUs > 64 || c.Desktop.MemoryBytes < 2<<30 {
		return errors.New("desktop resources are outside supported bounds")
	}
	if c.Desktop.Viewer != "remote-viewer" {
		return errors.New("only remote-viewer is supported")
	}
	if c.USB.DefaultFilesystem != "luks2-ext4" {
		return errors.New("only luks2-ext4 USB output is supported")
	}
	if c.Logging.Telemetry {
		return errors.New("telemetry cannot be enabled")
	}
	if !c.VPN.DisableIPv6IfNotTunneled {
		return errors.New("IPv6 must be disabled when the VPN does not tunnel it")
	}
	return nil
}
