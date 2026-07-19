package main

import (
	"strings"
	"testing"
)

func TestStartupFailureMessageIsStableAndRedacted(t *testing.T) {
	if !strings.Contains(daemonStartupFailureMessage, "DAEMON_START_FAILED") || !strings.Contains(daemonStartupFailureMessage, "verify the installed configuration") {
		t.Fatalf("startup failure message lacks stable code or remediation: %q", daemonStartupFailureMessage)
	}
	for _, forbidden := range []string{"%v", "%w", "PrivateKey", "magnet:", "/home/"} {
		if strings.Contains(daemonStartupFailureMessage, forbidden) {
			t.Fatalf("startup failure message contains unsafe fragment %q", forbidden)
		}
	}
}
