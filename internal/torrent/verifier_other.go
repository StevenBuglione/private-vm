//go:build !linux

package torrent

import "context"

type FilesystemVerifier struct{}

func NewFilesystemVerifier() *FilesystemVerifier { return &FilesystemVerifier{} }

func (*FilesystemVerifier) Verify(context.Context, Metadata) ([]FileDigest, error) {
	return nil, sealFailed()
}

var _ CompletedVerifier = (*FilesystemVerifier)(nil)
