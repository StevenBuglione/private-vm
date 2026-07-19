//go:build linux

package torrent

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type FilesystemVerifier struct {
	root string
}

func NewFilesystemVerifier() *FilesystemVerifier {
	return &FilesystemVerifier{root: QuarantineDownloadDir}
}

func newFilesystemVerifier(root string) (*FilesystemVerifier, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, invalidRequest()
	}
	return &FilesystemVerifier{root: root}, nil
}

func (verifier *FilesystemVerifier) Verify(ctx context.Context, metadata Metadata) ([]FileDigest, error) {
	if verifier == nil || ctx == nil || verifier.root == "" || metadata.SelectedSizeBytes == 0 {
		return nil, sealFailed()
	}
	rootFD, err := unix.Open(verifier.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, sealFailed()
	}
	defer unix.Close(rootFD)
	result := make([]FileDigest, 0)
	for _, expected := range metadata.Files {
		if !expected.Selected {
			continue
		}
		if err := ctx.Err(); err != nil {
			clearManifest(result)
			return nil, err
		}
		if validateRelativePath(expected.DisplayPath) != nil || strings.Contains(expected.DisplayPath, string(filepath.Separator)+".") {
			clearManifest(result)
			return nil, sealFailed()
		}
		fd, err := unix.Openat2(rootFD, expected.DisplayPath, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
		})
		if err != nil {
			clearManifest(result)
			return nil, sealFailed()
		}
		file := os.NewFile(uintptr(fd), "quarantine-file")
		entry, verifyErr := hashRegularFile(ctx, file, expected)
		closeErr := file.Close()
		if verifyErr != nil || closeErr != nil {
			clear(entry.SHA256[:])
			clearManifest(result)
			if isContextError(verifyErr) {
				return nil, verifyErr
			}
			return nil, sealFailed()
		}
		result = append(result, entry)
	}
	if len(result) == 0 {
		return nil, sealFailed()
	}
	return result, nil
}

func hashRegularFile(ctx context.Context, file *os.File, expected File) (FileDigest, error) {
	var stat unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size < 0 || uint64(stat.Size) != expected.SizeBytes {
		return FileDigest{}, errors.New("quarantine entry is not one exact regular file")
	}
	hash := sha256.New()
	buffer := make([]byte, 1<<20)
	defer clearBytes(buffer)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			return FileDigest{}, err
		}
		n, err := file.Read(buffer)
		if n > 0 {
			total += uint64(n)
			if total > expected.SizeBytes {
				return FileDigest{}, errors.New("quarantine entry exceeded metadata size")
			}
			if _, writeErr := hash.Write(buffer[:n]); writeErr != nil {
				return FileDigest{}, writeErr
			}
			clearBytes(buffer[:n])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || n == 0 {
			return FileDigest{}, errors.New("quarantine entry read failed")
		}
	}
	if total != expected.SizeBytes {
		return FileDigest{}, errors.New("quarantine entry size mismatch")
	}
	digest := hash.Sum(nil)
	var fixed [32]byte
	copy(fixed[:], digest)
	clearBytes(digest)
	return FileDigest{Path: expected.DisplayPath, SizeBytes: total, SHA256: fixed, SourceIndex: expected.Index}, nil
}

var _ CompletedVerifier = (*FilesystemVerifier)(nil)
