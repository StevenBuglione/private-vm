package transfer

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestReceiver(t *testing.T) {
	data := []byte("approved output")
	sum := sha256.Sum256(data)
	var out bytes.Buffer
	r, err := NewReceiver(Header{Name: "out.bin", Size: uint64(len(data)), SHA256: sum}, 1024, &out)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteChunk(0, data); err != nil {
		t.Fatal(err)
	}
	if err := r.Finish(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatal("data mismatch")
	}
}

func TestReceiverRejectsOffset(t *testing.T) {
	sum := sha256.Sum256([]byte("a"))
	r, _ := NewReceiver(Header{Name: "a", Size: 1, SHA256: sum}, 1, &bytes.Buffer{})
	if err := r.WriteChunk(1, []byte("a")); err == nil {
		t.Fatal("expected offset error")
	}
}
