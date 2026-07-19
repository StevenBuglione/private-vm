package secret

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

const publicFixture = "private-vm-public-secret-fixture"

func TestSecretReaderComparisonAndInputCopy(t *testing.T) {
	input := []byte(publicFixture)
	value, err := New(input)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Destroy()
	clear(input)

	var retained io.Reader
	if err := value.WithReader(func(reader io.Reader) error {
		retained = reader
		actual, readErr := io.ReadAll(reader)
		if readErr != nil {
			return readErr
		}
		if string(actual) != publicFixture {
			t.Fatal("protected value did not preserve the input")
		}
		clear(actual)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := retained.Read(make([]byte, 1)); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("retained view remained usable: %v", err)
	}
	matched, err := value.Equal([]byte(publicFixture))
	if err != nil || !matched {
		t.Fatalf("equal value did not match: matched=%t error=%v", matched, err)
	}
	matched, err = value.Equal([]byte("different-public-fixture"))
	if err != nil || matched {
		t.Fatalf("different value matched: matched=%t error=%v", matched, err)
	}
}

func TestSecretReaderInvalidatesAfterCallbackPanic(t *testing.T) {
	value, err := New([]byte(publicFixture))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Destroy()
	var retained io.Reader
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("callback did not panic")
			}
		}()
		_ = value.WithReader(func(reader io.Reader) error {
			retained = reader
			panic("public test panic")
		})
	}()
	if _, err := retained.Read(make([]byte, 1)); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("reader retained after panic: %v", err)
	}
}

func TestSecretValidationAndInertZeroValues(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty input error = %v", err)
	}
	if _, err := New(make([]byte, MaximumBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize input error = %v", err)
	}
	for name, value := range map[string]*Bytes{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			if err := value.WithReader(func(io.Reader) error { return nil }); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("WithReader error = %v", err)
			}
			if _, err := value.Equal(nil); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Equal error = %v", err)
			}
			if _, err := value.DupFile(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("DupFile error = %v", err)
			}
			value.Destroy()
			value.Destroy()
		})
	}
	value, err := New([]byte(publicFixture))
	if err != nil {
		t.Fatal(err)
	}
	if err := value.WithReader(nil); !errors.Is(err, ErrCallback) {
		t.Fatalf("nil callback error = %v", err)
	}
	want := errors.New("public callback failure")
	if err := value.WithReader(func(io.Reader) error { return want }); !errors.Is(err, want) {
		t.Fatalf("callback error = %v", err)
	}
	value.Destroy()
	if err := value.WithReader(func(io.Reader) error { return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("post-destroy error = %v", err)
	}
	if _, err := value.Equal(nil); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("post-destroy comparison error = %v", err)
	}
	if _, err := value.DupFile(); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("post-destroy duplicate error = %v", err)
	}
}

func TestCopiedHandleSharesOneCleanupOwner(t *testing.T) {
	value, err := New([]byte(publicFixture))
	if err != nil {
		t.Fatal(err)
	}
	copyOfHandle := *value
	copyOfHandle.Destroy()
	value.Destroy()
	if err := value.WithReader(func(io.Reader) error { return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("original handle remained live: %v", err)
	}
}

func TestConcurrentReadAndDestroyIsSerialized(t *testing.T) {
	value, err := New([]byte(publicFixture))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		_ = value.WithReader(func(reader io.Reader) error {
			close(started)
			<-release
			_, readErr := io.Copy(io.Discard, reader)
			return readErr
		})
	}()
	<-started
	destroyed := make(chan struct{})
	go func() {
		value.Destroy()
		close(destroyed)
	}()
	select {
	case <-destroyed:
		t.Fatal("Destroy did not wait for the active reader")
	default:
	}
	close(release)
	wait.Wait()
	<-destroyed
	if err := value.WithReader(func(io.Reader) error { return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("destroyed value remained live: %v", err)
	}
}

func TestSecretAlwaysRedacts(t *testing.T) {
	value, err := New([]byte(publicFixture))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Destroy()
	if value.String() != redacted || value.GoString() != redacted {
		t.Fatal("string methods did not redact")
	}
	for _, format := range []string{"%s", "%q", "%x", "%v", "%#v", "%+v"} {
		actual := fmt.Sprintf(format, value)
		if actual != redacted || strings.Contains(actual, publicFixture) {
			t.Fatalf("format %q was not redacted", format)
		}
	}
	copyOfHandle := *value
	for _, format := range []string{"%s", "%q", "%x", "%v", "%#v", "%+v"} {
		actual := fmt.Sprintf(format, copyOfHandle)
		if actual != redacted || strings.Contains(actual, publicFixture) {
			t.Fatalf("copied handle format %q was not redacted", format)
		}
	}
}

func TestSecretRejectsEverySupportedSerializationPath(t *testing.T) {
	value, err := New([]byte(publicFixture))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Destroy()
	tests := map[string]func() error{
		"json": func() error {
			_, marshalErr := json.Marshal(struct {
				Value *Bytes `json:"value"`
			}{value})
			return marshalErr
		},
		"text":   func() error { _, marshalErr := value.MarshalText(); return marshalErr },
		"binary": func() error { _, marshalErr := value.MarshalBinary(); return marshalErr },
		"gob": func() error {
			var destination bytes.Buffer
			return gob.NewEncoder(&destination).Encode(value)
		},
		"xml": func() error {
			return value.MarshalXML(xml.NewEncoder(io.Discard), xml.StartElement{Name: xml.Name{Local: "value"}})
		},
	}
	for name, serialize := range tests {
		t.Run(name, func(t *testing.T) {
			err := serialize()
			if !errors.Is(err, ErrSerialization) {
				t.Fatalf("serialization error = %v", err)
			}
			if strings.Contains(err.Error(), publicFixture) {
				t.Fatal("serialization error disclosed the fixture")
			}
		})
	}
	copyOfHandle := *value
	if _, err := json.Marshal(copyOfHandle); !errors.Is(err, ErrSerialization) {
		t.Fatalf("copied handle JSON error = %v", err)
	}
	if _, err := xml.Marshal(copyOfHandle); !errors.Is(err, ErrSerialization) {
		t.Fatalf("copied handle XML error = %v", err)
	}
	var destination bytes.Buffer
	if err := gob.NewEncoder(&destination).Encode(copyOfHandle); !errors.Is(err, ErrSerialization) {
		t.Fatalf("copied handle gob error = %v", err)
	}
}
