package guest

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadTokenExactLengthAndDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capability")
	value := repeatedToken(0x42)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := ReadToken(path)
	if err != nil {
		t.Fatal(err)
	}
	defer token.Destroy()
	file, err := token.DupFile()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	presented, err := io.ReadAll(io.LimitReader(file, TokenSize+1))
	if err != nil {
		t.Fatal(err)
	}
	if string(presented) != string(value) {
		t.Fatal("duplicated descriptor did not contain the exact capability")
	}
}

func TestReadTokenRejectsInvalidInput(t *testing.T) {
	directory := t.TempDir()
	for _, size := range []int{TokenSize - 1, TokenSize + 1} {
		path := filepath.Join(directory, fmt.Sprintf("capability-%d", size))
		if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadToken(path); err == nil {
			t.Fatalf("ReadToken accepted %d bytes", size)
		}
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, repeatedToken(1), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadToken(link); err == nil {
		t.Fatal("ReadToken followed a symlink")
	}
}

func TestTokenRedactionAndDestruction(t *testing.T) {
	token, err := TokenFromBytes(repeatedToken(0x7a))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%v %#v", token, token); strings.Contains(got, "eno6") || got != "[REDACTED] [REDACTED]" {
		t.Fatalf("unsafe token formatting: %q", got)
	}
	if _, err := json.Marshal(token); err == nil {
		t.Fatal("token JSON serialization succeeded")
	}
	token.Destroy()
	if _, err := token.outgoingContext(t.Context()); err == nil {
		t.Fatal("destroyed token remained usable")
	}
}

func repeatedToken(value byte) []byte {
	return []byte(strings.Repeat(string([]byte{value}), TokenSize))
}
