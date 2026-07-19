package image

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type classifiedCause struct{ marker string }

func (cause *classifiedCause) Error() string { return cause.marker }

func TestErrorFormattingNeverExposesWrappedCause(t *testing.T) {
	const privateMarker = "registry-filesystem-private-marker"
	cause := &classifiedCause{marker: privateMarker}
	err := imageError(
		CodeDownloadFailed,
		"An OCI component could not be downloaded.",
		"Retry the bounded image pull.",
		cause,
	)

	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%+q"}
	for _, format := range formats {
		if rendered := fmt.Sprintf(format, err); strings.Contains(rendered, privateMarker) {
			t.Fatalf("format %q exposed wrapped cause: %q", format, rendered)
		}
	}
	wrapped := fmt.Errorf("safe outer context: %w", err)
	for _, format := range formats {
		if rendered := fmt.Sprintf(format, wrapped); strings.Contains(rendered, privateMarker) {
			t.Fatalf("wrapped format %q exposed cause: %q", format, rendered)
		}
	}
	data, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(data), privateMarker) {
		t.Fatalf("JSON exposed wrapped cause: %s", data)
	}

	if !errors.Is(err, cause) {
		t.Fatal("safe formatting broke errors.Is cause access")
	}
	var imageErr *Error
	if !errors.As(err, &imageErr) || imageErr.Code() != CodeDownloadFailed {
		t.Fatalf("safe formatting broke image errors.As: %#v", imageErr)
	}
	var classified *classifiedCause
	if !errors.As(err, &classified) || classified != cause {
		t.Fatalf("safe formatting broke cause errors.As: %#v", classified)
	}
	if strings.Contains(imageErr.GoString(), privateMarker) {
		t.Fatalf("GoString exposed wrapped cause: %q", imageErr.GoString())
	}
}
