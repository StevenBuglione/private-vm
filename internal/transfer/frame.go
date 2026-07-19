package transfer

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
)

const DefaultMaxChunk = 1 << 20

type Header struct {
	Name      string
	Size      uint64
	SHA256    [32]byte
	MediaType string
}

func (h Header) Validate(maxSize uint64) error {
	if h.Name == "" || h.Name == "." || h.Name == ".." || len(h.Name) > 255 ||
		strings.ContainsAny(h.Name, "/\\\x00\r\n") {
		return errors.New("logical name must be one safe path component")
	}
	for _, value := range h.Name {
		if value < 0x20 || value == 0x7f {
			return errors.New("logical name contains a control character")
		}
	}
	if h.Size > maxSize {
		return fmt.Errorf("size %d exceeds limit %d", h.Size, maxSize)
	}
	if len(h.MediaType) > 255 || strings.ContainsAny(h.MediaType, "\x00\r\n") {
		return errors.New("media type is invalid")
	}
	return nil
}

type Receiver struct {
	expected Header
	written  uint64
	hash     hash.Hash
	writer   io.Writer
}

func NewReceiver(header Header, maxSize uint64, writer io.Writer) (*Receiver, error) {
	if err := header.Validate(maxSize); err != nil {
		return nil, err
	}
	if writer == nil {
		return nil, errors.New("writer required")
	}
	return &Receiver{expected: header, hash: sha256.New(), writer: writer}, nil
}

func (r *Receiver) WriteChunk(offset uint64, data []byte) error {
	if offset != r.written {
		return fmt.Errorf("non-contiguous offset: got %d want %d", offset, r.written)
	}
	if len(data) > DefaultMaxChunk {
		return errors.New("chunk exceeds maximum")
	}
	if r.written+uint64(len(data)) > r.expected.Size {
		return errors.New("stream exceeds declared size")
	}
	if _, err := r.writer.Write(data); err != nil {
		return err
	}
	_, _ = r.hash.Write(data)
	r.written += uint64(len(data))
	return nil
}

func (r *Receiver) Finish() error {
	if r.written != r.expected.Size {
		return fmt.Errorf("short stream: got %d want %d", r.written, r.expected.Size)
	}
	got := r.hash.Sum(nil)
	if !equal(got, r.expected.SHA256[:]) {
		return errors.New("SHA-256 mismatch")
	}
	return nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var mismatch byte
	for i := range a {
		mismatch |= a[i] ^ b[i]
	}
	return mismatch == 0
}
