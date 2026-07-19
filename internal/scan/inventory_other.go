//go:build !linux

package scan

import "context"

func BuildInventory(context.Context, string, InventoryLimits, MIMEClassifier) (Inventory, error) {
	return Inventory{}, scanError("SCAN_PLATFORM_UNSUPPORTED", "Safe quarantine traversal is unavailable on this platform.", "Run the scanner inside the supported Linux guest image.", nil)
}
