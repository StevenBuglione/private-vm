package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunRejectsUnsupportedAndSecretBearingInput(t *testing.T) {
	for _, test := range []struct {
		name      string
		arguments []string
		stdin     string
		code      string
	}{
		{"missing", nil, "", "usage"},
		{"unsupported", []string{"shell"}, "", "RELEASE_INVALID"},
		{"credential-newline", []string{"publish", "--prepared", "/tmp/prepared", "--tag", "v1.2.3", "--source-commit", strings.Repeat("a", 40), "--deb-provenance", "/tmp/deb", "--rpm-provenance", "/tmp/rpm", "--generic-provenance", "/tmp/generic", "--token-stdin"}, "private-value\n", "RELEASE_INVALID"},
		{"noncanonical-verify", []string{"verify", "--tag", "latest", "--source-commit", strings.Repeat("a", 40)}, "", "RELEASE_INVALID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			err := run(context.Background(), test.arguments, strings.NewReader(test.stdin), &output)
			if err == nil || !strings.Contains(err.Error(), test.code) || strings.Contains(err.Error(), "private-value") || output.Len() != 0 {
				t.Fatalf("unexpected result: %v %q", err, output.String())
			}
		})
	}
}
func TestWriteJSONIsOneBoundedRecord(t *testing.T) {
	var output bytes.Buffer
	if err := writeJSON(&output, struct {
		OK bool `json:"ok"`
	}{OK: true}); err != nil {
		t.Fatal(err)
	}
	if output.String() != "{\"ok\":true}\n" {
		t.Fatalf("unexpected JSON: %q", output.String())
	}
}
