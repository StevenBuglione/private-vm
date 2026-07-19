package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

func TestFileSelectionIsBoundedBeforeSplitting(t *testing.T) {
	for _, value := range []string{
		strings.Repeat("9", maximumFileSelectionBytes+1),
		strings.Repeat(",", maximumFileSelectionBytes+1),
	} {
		_, err := parseFileSelection(value)
		var applicationError *apperror.Error
		if !errors.As(err, &applicationError) || applicationError.ExitCode != exitcode.Usage {
			t.Fatalf("error=%v", err)
		}
	}
}

func TestFileSelectionProducesTypedIndexes(t *testing.T) {
	indexes, err := parseFileSelection("1,2,4294967295")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{1, 2, 4294967295}
	for index := range want {
		if indexes[index] != want[index] {
			t.Fatalf("indexes=%v want=%v", indexes, want)
		}
	}
}
