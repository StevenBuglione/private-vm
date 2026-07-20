//go:build !linux

package scan

import (
	"context"
	"io"
)

func BuildInventory(context.Context, string, InventoryLimits, MIMEClassifier) (Inventory, error) {
	return Inventory{}, scanError("SCAN_PLATFORM_UNSUPPORTED", "Safe quarantine traversal is unavailable on this platform.", "Run the scanner inside the supported Linux guest image.", nil)
}

func OpenInventoryEntry(context.Context, string, InventoryEntry) (io.ReadCloser, error) {
	return nil, scanError("SCAN_PLATFORM_UNSUPPORTED", "Safe quarantine traversal is unavailable on this platform.", "Run the scanner inside the supported Linux guest image.", nil)
}
