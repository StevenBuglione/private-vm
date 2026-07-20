//go:build !linux

package scan

import "os"

func extractionParentIsTmpfs(string) bool { return false }

func captureFileInfoIdentity(info os.FileInfo) fileInfoIdentity {
	return fileInfoIdentity{mode: info.Mode(), native: info}
}

func sameFileInfoIdentity(info os.FileInfo, identity fileInfoIdentity) bool {
	previous, ok := identity.native.(os.FileInfo)
	return ok && info.Mode() == identity.mode && os.SameFile(info, previous)
}
