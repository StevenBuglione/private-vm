// Package config loads the versioned, non-secret private-vm configuration.
// Effective configurations are immutable value objects: callers can inspect
// scalar values through getters but cannot mutate a shared snapshot.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
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

const (
	minimumDesktopMemory = uint64(2 << 30)
	maximumDesktopMemory = uint64(256 << 30)
	maximumScratchBudget = uint64(1 << 40)
)

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}/[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
	registryPattern   = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*(?::(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$`)
	profilePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

// Config is one immutable effective configuration snapshot.
type Config struct {
	schemaVersion int
	strict        bool
	imageSource   ImageSource
	runtime       Runtime
	desktop       Desktop
	vpn           VPN
	usb           USB
	logging       Logging
}

type ImageSource struct {
	registry           string
	repository         string
	channel            string
	requireAttestation bool
}

type Runtime struct {
	directory             string
	imageCache            string
	scratchDirectory      string
	smallScratchMaxBytes  uint64
	cleanupTimeoutSeconds int
}

type Desktop struct {
	bundle      string
	viewer      string
	audio       bool
	memoryBytes uint64
	vcpus       uint32
}

type VPN struct {
	profileName              string
	disableIPv6IfNotTunneled bool
}

type USB struct {
	requireUSBGuard   bool
	defaultFilesystem string
}

type Logging struct {
	persistentLifecycleMetadata bool
	telemetry                   bool
}

func (c Config) SchemaVersion() int       { return c.schemaVersion }
func (c Config) Strict() bool             { return c.strict }
func (c Config) ImageSource() ImageSource { return c.imageSource }
func (c Config) Runtime() Runtime         { return c.runtime }
func (c Config) Desktop() Desktop         { return c.desktop }
func (c Config) VPN() VPN                 { return c.vpn }
func (c Config) USB() USB                 { return c.usb }
func (c Config) Logging() Logging         { return c.logging }

func (c ImageSource) Registry() string              { return c.registry }
func (c ImageSource) Repository() string            { return c.repository }
func (c ImageSource) Channel() string               { return c.channel }
func (c ImageSource) RequireAttestation() bool      { return c.requireAttestation }
func (c Runtime) Directory() string                 { return c.directory }
func (c Runtime) ImageCache() string                { return c.imageCache }
func (c Runtime) ScratchDirectory() string          { return c.scratchDirectory }
func (c Runtime) SmallScratchMaxBytes() uint64      { return c.smallScratchMaxBytes }
func (c Runtime) CleanupTimeoutSeconds() int        { return c.cleanupTimeoutSeconds }
func (c Desktop) Bundle() string                    { return c.bundle }
func (c Desktop) Viewer() string                    { return c.viewer }
func (c Desktop) Audio() bool                       { return c.audio }
func (c Desktop) MemoryBytes() uint64               { return c.memoryBytes }
func (c Desktop) VCPUs() uint32                     { return c.vcpus }
func (c VPN) ProfileName() string                   { return c.profileName }
func (c VPN) DisableIPv6IfNotTunneled() bool        { return c.disableIPv6IfNotTunneled }
func (c USB) RequireUSBGuard() bool                 { return c.requireUSBGuard }
func (c USB) DefaultFilesystem() string             { return c.defaultFilesystem }
func (c Logging) PersistentLifecycleMetadata() bool { return c.persistentLifecycleMetadata }
func (c Logging) Telemetry() bool                   { return c.telemetry }

// wireConfig is the strict durable/effective representation. It is private so
// callers cannot mutate Config by retaining a decoded map or nested pointer.
type wireConfig struct {
	SchemaVersion int             `toml:"schema_version" json:"schema_version"`
	Strict        bool            `toml:"strict" json:"strict"`
	ImageSource   wireImageSource `toml:"image_source" json:"image_source"`
	Runtime       wireRuntime     `toml:"runtime" json:"runtime"`
	Desktop       wireDesktop     `toml:"desktop" json:"desktop"`
	VPN           wireVPN         `toml:"vpn" json:"vpn"`
	USB           wireUSB         `toml:"usb" json:"usb"`
	Logging       wireLogging     `toml:"logging" json:"logging"`
}

type wireImageSource struct {
	Registry           string `toml:"registry" json:"registry"`
	Repository         string `toml:"repository" json:"repository"`
	Channel            string `toml:"channel" json:"channel"`
	RequireAttestation bool   `toml:"require_attestation" json:"require_attestation"`
}

type wireRuntime struct {
	Directory             string `toml:"directory" json:"directory"`
	ImageCache            string `toml:"image_cache" json:"image_cache"`
	ScratchDirectory      string `toml:"scratch_directory" json:"scratch_directory"`
	SmallScratchMaxBytes  uint64 `toml:"small_scratch_max_bytes" json:"small_scratch_max_bytes"`
	CleanupTimeoutSeconds int    `toml:"cleanup_timeout_seconds" json:"cleanup_timeout_seconds"`
}

type wireDesktop struct {
	Bundle      string `toml:"bundle" json:"bundle"`
	Viewer      string `toml:"viewer" json:"viewer"`
	Audio       bool   `toml:"audio" json:"audio"`
	MemoryBytes uint64 `toml:"memory_bytes" json:"memory_bytes"`
	VCPUs       uint32 `toml:"vcpus" json:"vcpus"`
}

type wireVPN struct {
	ProfileName              string `toml:"profile_name" json:"profile_name"`
	DisableIPv6IfNotTunneled bool   `toml:"disable_ipv6_if_not_tunneled" json:"disable_ipv6_if_not_tunneled"`
}

type wireUSB struct {
	RequireUSBGuard   bool   `toml:"require_usbguard" json:"require_usbguard"`
	DefaultFilesystem string `toml:"default_filesystem" json:"default_filesystem"`
}

type wireLogging struct {
	PersistentLifecycleMetadata bool `toml:"persistent_lifecycle_metadata" json:"persistent_lifecycle_metadata"`
	Telemetry                   bool `toml:"telemetry" json:"telemetry"`
}

func Defaults() Config {
	return configFromWire(wireConfig{
		SchemaVersion: SchemaVersion,
		Strict:        true,
		ImageSource: wireImageSource{
			Registry: DefaultRegistry, Repository: OfficialRepository,
			Channel: "stable", RequireAttestation: true,
		},
		Runtime: wireRuntime{
			Directory: DefaultRuntimePath, ImageCache: DefaultImageCache,
			ScratchDirectory: DefaultScratchPath, SmallScratchMaxBytes: 16 << 30,
			CleanupTimeoutSeconds: DefaultCleanupLimit,
		},
		Desktop: wireDesktop{
			Bundle: "development", Viewer: "remote-viewer",
			MemoryBytes: 16 << 30, VCPUs: 8,
		},
		VPN: wireVPN{ProfileName: "proton-p2p", DisableIPv6IfNotTunneled: true},
		USB: wireUSB{RequireUSBGuard: true, DefaultFilesystem: "luks2-ext4"},
	})
}

func configFromWire(value wireConfig) Config {
	return Config{
		schemaVersion: value.SchemaVersion,
		strict:        value.Strict,
		imageSource: ImageSource{
			registry: value.ImageSource.Registry, repository: value.ImageSource.Repository,
			channel: value.ImageSource.Channel, requireAttestation: value.ImageSource.RequireAttestation,
		},
		runtime: Runtime{
			directory: value.Runtime.Directory, imageCache: value.Runtime.ImageCache,
			scratchDirectory:      value.Runtime.ScratchDirectory,
			smallScratchMaxBytes:  value.Runtime.SmallScratchMaxBytes,
			cleanupTimeoutSeconds: value.Runtime.CleanupTimeoutSeconds,
		},
		desktop: Desktop{
			bundle: value.Desktop.Bundle, viewer: value.Desktop.Viewer, audio: value.Desktop.Audio,
			memoryBytes: value.Desktop.MemoryBytes, vcpus: value.Desktop.VCPUs,
		},
		vpn: VPN{
			profileName:              value.VPN.ProfileName,
			disableIPv6IfNotTunneled: value.VPN.DisableIPv6IfNotTunneled,
		},
		usb: USB{
			requireUSBGuard:   value.USB.RequireUSBGuard,
			defaultFilesystem: value.USB.DefaultFilesystem,
		},
		logging: Logging{
			persistentLifecycleMetadata: value.Logging.PersistentLifecycleMetadata,
			telemetry:                   value.Logging.Telemetry,
		},
	}
}

func (c Config) wire() wireConfig {
	return wireConfig{
		SchemaVersion: c.schemaVersion,
		Strict:        c.strict,
		ImageSource: wireImageSource{
			Registry: c.imageSource.registry, Repository: c.imageSource.repository,
			Channel: c.imageSource.channel, RequireAttestation: c.imageSource.requireAttestation,
		},
		Runtime: wireRuntime{
			Directory: c.runtime.directory, ImageCache: c.runtime.imageCache,
			ScratchDirectory:      c.runtime.scratchDirectory,
			SmallScratchMaxBytes:  c.runtime.smallScratchMaxBytes,
			CleanupTimeoutSeconds: c.runtime.cleanupTimeoutSeconds,
		},
		Desktop: wireDesktop{
			Bundle: c.desktop.bundle, Viewer: c.desktop.viewer, Audio: c.desktop.audio,
			MemoryBytes: c.desktop.memoryBytes, VCPUs: c.desktop.vcpus,
		},
		VPN: wireVPN{
			ProfileName:              c.vpn.profileName,
			DisableIPv6IfNotTunneled: c.vpn.disableIPv6IfNotTunneled,
		},
		USB: wireUSB{
			RequireUSBGuard:   c.usb.requireUSBGuard,
			DefaultFilesystem: c.usb.defaultFilesystem,
		},
		Logging: wireLogging{
			PersistentLifecycleMetadata: c.logging.persistentLifecycleMetadata,
			Telemetry:                   c.logging.telemetry,
		},
	}
}

// MarshalJSON emits the complete effective snapshot, never a partial layer.
func (c Config) MarshalJSON() ([]byte, error) { return json.Marshal(c.wire()) }

func (c Config) Validate() error {
	if c.schemaVersion != SchemaVersion {
		return invalid("The configuration schema version is unsupported.", "Use schema_version = 1 or run a documented migration.")
	}
	if !validRegistry(c.imageSource.registry) ||
		!repositoryPattern.MatchString(c.imageSource.repository) || len(c.imageSource.repository) > 128 {
		return invalid("The image source identity is invalid.", "Set a registry and an owner/repository image source.")
	}
	if !c.imageSource.requireAttestation {
		return invalid("Every image source requires provenance attestation.", "Set image_source.require_attestation = true.")
	}
	if c.imageSource.channel != "stable" && c.imageSource.channel != "edge" {
		return invalid("The image channel is unsupported.", "Use the stable or edge channel.")
	}
	if c.runtime.directory != DefaultRuntimePath {
		return invalid("The volatile runtime directory is fixed for v1.", "Set runtime.directory = /run/private-vm.")
	}
	if c.runtime.imageCache != DefaultImageCache || c.runtime.scratchDirectory != DefaultScratchPath {
		return invalid("The image cache and scratch paths are fixed for v1.", "Use /var/lib/private-vm/images and /var/lib/private-vm/scratch.")
	}
	if c.runtime.smallScratchMaxBytes == 0 || c.runtime.smallScratchMaxBytes > maximumScratchBudget {
		return invalid("The small-session scratch budget is outside supported bounds.", "Set it between 1 byte and 1 TiB.")
	}
	if c.runtime.cleanupTimeoutSeconds < 5 || c.runtime.cleanupTimeoutSeconds > 300 {
		return invalid("The cleanup timeout is outside supported bounds.", "Set it between 5 and 300 seconds.")
	}
	if c.desktop.vcpus < 1 || c.desktop.vcpus > 64 ||
		c.desktop.memoryBytes < minimumDesktopMemory || c.desktop.memoryBytes > maximumDesktopMemory {
		return invalid("Desktop resources are outside supported bounds.", "Use 1-64 vCPUs and 2-256 GiB of memory.")
	}
	if c.desktop.viewer != "remote-viewer" {
		return invalid("The desktop viewer is unsupported.", "Use remote-viewer.")
	}
	switch c.desktop.bundle {
	case "basic", "office", "development":
	default:
		return invalid("The desktop bundle is unsupported.", "Use basic, office, or development.")
	}
	if !profilePattern.MatchString(c.vpn.profileName) {
		return invalid("The VPN profile name is invalid.", "Use 1-64 letters, digits, dots, underscores, or hyphens.")
	}
	if !c.vpn.disableIPv6IfNotTunneled {
		return invalid("IPv6 must fail closed when it is not tunneled.", "Set vpn.disable_ipv6_if_not_tunneled = true.")
	}
	if !c.usb.requireUSBGuard {
		return invalid("USBGuard identity enforcement is mandatory.", "Set usb.require_usbguard = true.")
	}
	if c.usb.defaultFilesystem != "luks2-ext4" {
		return invalid("The USB output filesystem is unsupported.", "Use luks2-ext4.")
	}
	if c.logging.telemetry {
		return invalid("Telemetry cannot be enabled.", "Set logging.telemetry = false.")
	}
	return nil
}

func safeHostPath(path string) bool {
	if len(path) == 0 || len(path) > 4096 || !utf8.ValidString(path) ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	switch path {
	case "/", "/boot", "/dev", "/etc", "/home", "/media", "/mnt", "/proc", "/root", "/run", "/sys", "/tmp", "/usr", "/var", "/var/tmp", DefaultRuntimePath:
		return false
	}
	return true
}

func validRegistry(registry string) bool {
	if len(registry) == 0 || len(registry) > 255 || !registryPattern.MatchString(registry) {
		return false
	}
	host := registry
	if separator := strings.LastIndexByte(registry, ':'); separator >= 0 {
		host = registry[:separator]
		port, err := strconv.ParseUint(registry[separator+1:], 10, 16)
		if err != nil || port == 0 {
			return false
		}
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// Overrides is the closed set of non-secret command-line configuration
// overrides. Pointers preserve the distinction between absent and zero/false.
type Overrides struct {
	Strict      *bool
	ImageSource ImageSourceOverrides
	Runtime     RuntimeOverrides
	Desktop     DesktopOverrides
	VPN         VPNOverrides
	USB         USBOverrides
	Logging     LoggingOverrides
}

type ImageSourceOverrides struct {
	Registry, Repository, Channel *string
	RequireAttestation            *bool
}
type RuntimeOverrides struct {
	Directory, ImageCache, ScratchDirectory *string
	SmallScratchMaxBytes                    *uint64
	CleanupTimeoutSeconds                   *int
}
type DesktopOverrides struct {
	Bundle, Viewer *string
	Audio          *bool
	MemoryBytes    *uint64
	VCPUs          *uint32
}
type VPNOverrides struct {
	ProfileName              *string
	DisableIPv6IfNotTunneled *bool
}
type USBOverrides struct {
	RequireUSBGuard   *bool
	DefaultFilesystem *string
}
type LoggingOverrides struct {
	PersistentLifecycleMetadata *bool
	Telemetry                   *bool
}

func applyOverrides(value *wireConfig, overrides Overrides) {
	set(overrides.Strict, &value.Strict)
	set(overrides.ImageSource.Registry, &value.ImageSource.Registry)
	set(overrides.ImageSource.Repository, &value.ImageSource.Repository)
	set(overrides.ImageSource.Channel, &value.ImageSource.Channel)
	set(overrides.ImageSource.RequireAttestation, &value.ImageSource.RequireAttestation)
	set(overrides.Runtime.Directory, &value.Runtime.Directory)
	set(overrides.Runtime.ImageCache, &value.Runtime.ImageCache)
	set(overrides.Runtime.ScratchDirectory, &value.Runtime.ScratchDirectory)
	set(overrides.Runtime.SmallScratchMaxBytes, &value.Runtime.SmallScratchMaxBytes)
	set(overrides.Runtime.CleanupTimeoutSeconds, &value.Runtime.CleanupTimeoutSeconds)
	set(overrides.Desktop.Bundle, &value.Desktop.Bundle)
	set(overrides.Desktop.Viewer, &value.Desktop.Viewer)
	set(overrides.Desktop.Audio, &value.Desktop.Audio)
	set(overrides.Desktop.MemoryBytes, &value.Desktop.MemoryBytes)
	set(overrides.Desktop.VCPUs, &value.Desktop.VCPUs)
	set(overrides.VPN.ProfileName, &value.VPN.ProfileName)
	set(overrides.VPN.DisableIPv6IfNotTunneled, &value.VPN.DisableIPv6IfNotTunneled)
	set(overrides.USB.RequireUSBGuard, &value.USB.RequireUSBGuard)
	set(overrides.USB.DefaultFilesystem, &value.USB.DefaultFilesystem)
	set(overrides.Logging.PersistentLifecycleMetadata, &value.Logging.PersistentLifecycleMetadata)
	set(overrides.Logging.Telemetry, &value.Logging.Telemetry)
}

func set[T any](source *T, destination *T) {
	if source != nil {
		*destination = *source
	}
}

// Error is a stable, redacted configuration failure with remediation.
type Error struct {
	Code        string
	Message     string
	Remediation string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s Remediation: %s", e.Code, e.Message, e.Remediation)
}

func invalid(message, remediation string) error {
	return &Error{Code: "CONFIG_INVALID", Message: message, Remediation: remediation}
}

func errorCode(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return ""
}
