package scan

import (
	"bytes"
	"context"
	"mime"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
)

const (
	DefaultInventoryPrefixBytes = 64 << 10
	MaximumInventoryPathBytes   = 4096
)

type InventoryLimits struct {
	MaxFiles       uint64
	MaxInputBytes  uint64
	MaxPathBytes   int
	MaxPrefixBytes int
}

type InventoryEntry struct {
	RelativePath       string
	SizeBytes          uint64
	SHA256             string
	DetectedMIME       string
	ExtensionMIME      string
	ExtensionAgreement bool
	Mode               uint32
	Device             uint64
	Inode              uint64
}

type Inventory struct {
	Entries    []InventoryEntry
	TotalBytes uint64
}

// MIMEClassifier receives only a bounded content prefix. Implementations must
// not require a user filename, write the prefix, or retain it after returning.
type MIMEClassifier interface {
	Classify(context.Context, []byte) (string, error)
}

type MIMEClassifierFunc func(context.Context, []byte) (string, error)

func (f MIMEClassifierFunc) Classify(ctx context.Context, prefix []byte) (string, error) {
	return f(ctx, prefix)
}

// ConservativeMIMEClassifier is the dependency-free baseline. The production
// scanner may replace it with a pinned libmagic adapter that reads stdin; an
// unknown result remains application/octet-stream and is not promoted by safe
// policy.
type ConservativeMIMEClassifier struct{}

func (ConservativeMIMEClassifier) Classify(_ context.Context, prefix []byte) (string, error) {
	if len(prefix) == 0 {
		return "application/x-empty", nil
	}
	return strings.TrimSpace(strings.Split(http.DetectContentType(prefix), ";")[0]), nil
}

func normalizedExtensionMIME(relativePath string) string {
	extension := strings.ToLower(filepath.Ext(relativePath))
	if extension == "" {
		return ""
	}
	value := mime.TypeByExtension(extension)
	if index := strings.IndexByte(value, ';'); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(value)
}

func extensionAgrees(extensionMIME, detectedMIME string) bool {
	if extensionMIME == "" {
		return detectedMIME == "application/octet-stream"
	}
	if extensionMIME == detectedMIME {
		return true
	}
	extensionGroup, _, _ := strings.Cut(extensionMIME, "/")
	detectedGroup, _, _ := strings.Cut(detectedMIME, "/")
	return extensionGroup != "" && extensionGroup == detectedGroup &&
		(extensionGroup == "text" || extensionGroup == "image" || extensionGroup == "audio" || extensionGroup == "video")
}

func validateInventoryLimits(limits InventoryLimits) (InventoryLimits, error) {
	if limits.MaxFiles == 0 || limits.MaxFiles > 1_000_000 || limits.MaxInputBytes == 0 || limits.MaxInputBytes > 1<<40 {
		return InventoryLimits{}, scanError("SCAN_LIMIT_INVALID", "The inventory limits are outside supported bounds.", "Use finite nonzero file and byte limits within the documented policy ceilings.", nil)
	}
	if limits.MaxPathBytes == 0 {
		limits.MaxPathBytes = MaximumInventoryPathBytes
	}
	if limits.MaxPathBytes < 64 || limits.MaxPathBytes > MaximumInventoryPathBytes {
		return InventoryLimits{}, scanError("SCAN_LIMIT_INVALID", "The inventory path limit is outside supported bounds.", "Use a path limit from 64 through 4096 bytes.", nil)
	}
	if limits.MaxPrefixBytes == 0 {
		limits.MaxPrefixBytes = DefaultInventoryPrefixBytes
	}
	if limits.MaxPrefixBytes < 512 || limits.MaxPrefixBytes > 1<<20 {
		return InventoryLimits{}, scanError("SCAN_LIMIT_INVALID", "The content-identification prefix limit is outside supported bounds.", "Use a MIME prefix limit from 512 bytes through 1 MiB.", nil)
	}
	return limits, nil
}

func sortInventory(inventory *Inventory) {
	slices.SortFunc(inventory.Entries, func(left, right InventoryEntry) int {
		return bytes.Compare([]byte(left.RelativePath), []byte(right.RelativePath))
	})
}
