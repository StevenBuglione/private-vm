package commandexec

import (
	"context"
	"testing"
)

func TestRejectsRelativeExecutable(t *testing.T) {
	_, err := (OSExecutor{}).Run(context.Background(), "echo", "test")
	if err == nil {
		t.Fatal("expected relative path rejection")
	}
}
