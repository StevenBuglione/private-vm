package usb

import (
	"crypto/subtle"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrDigestSerialization = errors.New("USB transfer digests are internal and cannot be serialized")

// Digest keeps file hashes out of JSON, fmt output and receipts. File hashes
// are sensitive workflow metadata even though they are not secret keys.
type Digest struct{ value [32]byte }

func NewDigest(value [32]byte) Digest { return Digest{value: value} }

func (d Digest) Equal(other Digest) bool {
	return subtle.ConstantTimeCompare(d.value[:], other.value[:]) == 1
}

func (d Digest) IsZero() bool {
	var zero [32]byte
	return subtle.ConstantTimeCompare(d.value[:], zero[:]) == 1
}

func (d Digest) WithBytes(callback func([]byte) error) error {
	if callback == nil {
		return errors.New("digest callback is required")
	}
	copy := d.value
	defer clear(copy[:])
	return callback(copy[:])
}

func (Digest) String() string                 { return "[REDACTED-DIGEST]" }
func (Digest) GoString() string               { return "[REDACTED-DIGEST]" }
func (Digest) MarshalJSON() ([]byte, error)   { return nil, ErrDigestSerialization }
func (Digest) MarshalText() ([]byte, error)   { return nil, ErrDigestSerialization }
func (Digest) MarshalBinary() ([]byte, error) { return nil, ErrDigestSerialization }
func (Digest) GobEncode() ([]byte, error)     { return nil, ErrDigestSerialization }
func (Digest) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte("[REDACTED-DIGEST]")) }

var _ fmt.Formatter = Digest{}
var _ json.Marshaler = Digest{}
var _ encoding.TextMarshaler = Digest{}
var _ encoding.BinaryMarshaler = Digest{}
