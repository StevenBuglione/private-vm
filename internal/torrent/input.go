package torrent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"runtime"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

type InputKind string

const (
	InputMagnet   InputKind = "magnet"
	InputMetainfo InputKind = "metainfo"

	MaximumMagnetBytes   = 8 << 10
	MaximumMetainfoBytes = 16 << 20
	MaximumInputFrames   = 1024
)

// Input owns one bounded torrent source in protected volatile memory. Its
// formatter and serializers are deliberately disabled because magnets and
// metainfo are private session data.
type Input struct {
	kind  InputKind
	value *secret.Bytes
}

func NewInput(kind InputKind, raw []byte) (*Input, error) {
	if len(raw) == 0 {
		return nil, invalidInput()
	}
	maximum := inputMaximum(kind)
	if maximum == 0 {
		return nil, invalidRequest()
	}
	if len(raw) > maximum {
		return nil, inputTooLarge()
	}
	if kind == InputMagnet {
		if err := validateMagnet(raw); err != nil {
			return nil, err
		}
	} else if !looksLikeMetainfo(raw) {
		return nil, invalidInput()
	}
	value, err := secret.New(raw)
	if err != nil {
		return nil, invalidInput()
	}
	return &Input{kind: kind, value: value}, nil
}

func (input *Input) Kind() InputKind {
	if input == nil {
		return ""
	}
	return input.kind
}

func (input *Input) WithReader(ctx context.Context, callback func(context.Context, io.Reader) error) error {
	if input == nil || input.value == nil || ctx == nil || callback == nil {
		return invalidRequest()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return input.value.WithReader(func(reader io.Reader) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return callback(ctx, reader)
	})
}

func (input *Input) Destroy() {
	if input == nil {
		return
	}
	if input.value != nil {
		input.value.Destroy()
		input.value = nil
	}
	input.kind = ""
}

const redactedInput = "[REDACTED TORRENT INPUT]"

func (*Input) String() string   { return redactedInput }
func (*Input) GoString() string { return redactedInput }
func (*Input) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedInput))
}
func (*Input) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (*Input) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (*Input) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (*Input) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }
func (*Input) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

func inputMaximum(kind InputKind) int {
	switch kind {
	case InputMagnet:
		return MaximumMagnetBytes
	case InputMetainfo:
		return MaximumMetainfoBytes
	default:
		return 0
	}
}

func validateMagnet(raw []byte) error {
	if len(raw) > MaximumMagnetBytes {
		return inputTooLarge()
	}
	if !bytes.HasPrefix(raw, []byte("magnet:?")) || bytes.ContainsAny(raw, "\x00\r\n\t #") {
		return invalidInput()
	}
	query := raw[len("magnet:?"):]
	if len(query) == 0 {
		return invalidInput()
	}
	xtCount := 0
	for len(query) > 0 {
		field := query
		if index := bytes.IndexByte(query, '&'); index >= 0 {
			field, query = query[:index], query[index+1:]
		} else {
			query = nil
		}
		key, value, found := bytes.Cut(field, []byte{'='})
		if !found || len(key) == 0 || len(value) == 0 {
			return invalidInput()
		}
		if bytes.Equal(key, []byte("xt")) {
			xtCount++
			prefix := []byte("urn:btih:")
			if !bytes.HasPrefix(value, prefix) || !validBTIH(value[len(prefix):]) {
				return invalidInput()
			}
		}
	}
	if xtCount != 1 {
		return invalidInput()
	}
	return nil
}

func validBTIH(value []byte) bool {
	switch len(value) {
	case 40:
		for _, current := range value {
			if !(current >= '0' && current <= '9') && !(current >= 'a' && current <= 'f') && !(current >= 'A' && current <= 'F') {
				return false
			}
		}
		return true
	case 32:
		for _, current := range value {
			if !(current >= 'A' && current <= 'Z') && !(current >= '2' && current <= '7') {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func looksLikeMetainfo(raw []byte) bool {
	// Full bencode validation remains qBittorrent's bounded guest-local job.
	// This cheap gate rejects obvious wrong inputs before protected transport.
	return len(raw) >= 2 && raw[0] == 'd' && raw[len(raw)-1] == 'e' && !bytes.Contains(raw, []byte{0})
}

func clearBytes(value []byte) {
	clear(value)
	runtime.KeepAlive(value)
}

var _ fmt.Formatter = (*Input)(nil)
var _ json.Marshaler = (*Input)(nil)
var _ xml.Marshaler = (*Input)(nil)
