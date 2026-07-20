//go:build !linux

package scan

import "os"

func trustedExecutablePlatform(string, os.FileInfo) bool { return false }
