package usb

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestDigestNeverSerializesOrFormats(t *testing.T) {
	var value [32]byte
	copy(value[:], []byte("sensitive-hash-fixture"))
	digest := NewDigest(value)
	if _, err := json.Marshal(digest); err == nil {
		t.Fatal("digest serialized")
	}
	for _, rendered := range []string{fmt.Sprint(digest), fmt.Sprintf("%v", digest), fmt.Sprintf("%+v", digest), fmt.Sprintf("%#v", digest)} {
		if strings.Contains(rendered, fmt.Sprintf("%x", value[:])) || rendered != "[REDACTED-DIGEST]" {
			t.Fatalf("unsafe digest rendering: %q", rendered)
		}
	}
}
