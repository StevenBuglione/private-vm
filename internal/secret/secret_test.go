package secret

import "testing"

func TestSecretRedactsAndDestroys(t *testing.T) {
	s, err := New([]byte("sensitive"))
	if err != nil {
		t.Fatal(err)
	}
	if s.String() != "[REDACTED]" {
		t.Fatal("secret was not redacted")
	}
	s.Destroy()
	if err := s.With(func([]byte) error { return nil }); err == nil {
		t.Fatal("expected destroyed secret error")
	}
}
