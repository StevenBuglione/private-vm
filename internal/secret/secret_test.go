package secret

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSecretRedactsAndDestroys(t *testing.T) {
	s, err := New([]byte("sensitive"))
	if err != nil {
		t.Fatal(err)
	}
	if s.String() != "[REDACTED]" || fmt.Sprintf("%#v", s) != "[REDACTED]" {
		t.Fatal("secret was not redacted")
	}
	if _, err := json.Marshal(s); err == nil {
		t.Fatal("secret unexpectedly serialized")
	}
	s.Destroy()
	s.Destroy()
	if err := s.With(func([]byte) error { return nil }); err == nil {
		t.Fatal("expected destroyed secret error")
	}
}
