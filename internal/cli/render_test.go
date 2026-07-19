package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

func TestRendererSuccessJSONGolden(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	payload := VersionPayload{
		Version: "1.2.3<rc>", Commit: "0123456789abcdef", Date: "2026-07-18T12:00:00Z",
		GoVersion: "go1.26.5", OS: "linux", Arch: "amd64",
	}

	if err := NewRenderer(true).Success(&output, CodeVersion, payload); err != nil {
		t.Fatalf("render success: %v", err)
	}
	want := "{\"schema_version\":1,\"ok\":true,\"code\":\"VERSION_REPORTED\",\"data\":{\"version\":\"1.2.3<rc>\",\"commit\":\"0123456789abcdef\",\"date\":\"2026-07-18T12:00:00Z\",\"go_version\":\"go1.26.5\",\"os\":\"linux\",\"arch\":\"amd64\"}}\n"
	if output.String() != want {
		t.Fatalf("unexpected JSON\nwant: %s\n got: %s", want, output.String())
	}
	if strings.Contains(output.String(), "\\u003c") {
		t.Fatal("HTML escaping was unexpectedly enabled")
	}
}

func TestRendererDoctorJSONGolden(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	payload := DoctorPayload{
		Runnable: false,
		Diagnostics: []DoctorDiagnostic{{
			Code: "HOST_SWAP_ACTIVE", Severity: "blocking", Summary: "Disk-backed swap is active.",
			Remediation: "Disable swap and retry.", Overridable: false,
		}},
	}

	if err := NewRenderer(true).Success(&output, CodeDoctorReport, payload); err != nil {
		t.Fatalf("render doctor report: %v", err)
	}
	want := "{\"schema_version\":1,\"ok\":true,\"code\":\"DOCTOR_REPORT\",\"data\":{\"runnable\":false,\"diagnostics\":[{\"code\":\"HOST_SWAP_ACTIVE\",\"severity\":\"blocking\",\"summary\":\"Disk-backed swap is active.\",\"remediation\":\"Disable swap and retry.\",\"overridable\":false}]}}\n"
	if output.String() != want {
		t.Fatalf("unexpected JSON\nwant: %s\n got: %s", want, output.String())
	}
}

func TestRendererDoctorUsesEmptyArrayForNoDiagnostics(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := NewRenderer(true).Success(&output, CodeDoctorReport, DoctorPayload{Runnable: true}); err != nil {
		t.Fatalf("render empty doctor report: %v", err)
	}
	want := "{\"schema_version\":1,\"ok\":true,\"code\":\"DOCTOR_REPORT\",\"data\":{\"runnable\":true,\"diagnostics\":[]}}\n"
	if output.String() != want {
		t.Fatalf("unexpected JSON\nwant: %s\n got: %s", want, output.String())
	}
}

func TestRendererErrorJSONGoldenOmitsWrappedCause(t *testing.T) {
	t.Parallel()
	const secret = "PRIVATE-KEY-MUST-NOT-APPEAR"
	app := apperror.Wrap(
		"VPN_PROFILE_INVALID", exitcode.Network, "The VPN profile is invalid.",
		"Import a Proton WireGuard profile without hooks.", errors.New(secret),
	)
	app.SessionID = "pvm-11111111111111111111111111111111"
	var output bytes.Buffer

	if err := NewRenderer(true).Error(&output, app); err != nil {
		t.Fatalf("render error: %v", err)
	}
	want := "{\"schema_version\":1,\"ok\":false,\"code\":\"VPN_PROFILE_INVALID\",\"exit_code\":13,\"message\":\"The VPN profile is invalid.\",\"remediation\":\"Import a Proton WireGuard profile without hooks.\",\"session_id\":\"pvm-11111111111111111111111111111111\"}\n"
	if output.String() != want {
		t.Fatalf("unexpected JSON\nwant: %s\n got: %s", want, output.String())
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("wrapped error cause was serialized")
	}
}

func TestRendererEventJSONGolden(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	data := ProgressPayload{Current: 64, Total: 128, Unit: "MiB"}

	if err := NewRenderer(true).Event(&output, "IMAGE_PULL_PROGRESS", 7, "pvm-11111111111111111111111111111111", data); err != nil {
		t.Fatalf("render event: %v", err)
	}
	want := "{\"schema_version\":1,\"ok\":true,\"code\":\"IMAGE_PULL_PROGRESS\",\"sequence\":7,\"session_id\":\"pvm-11111111111111111111111111111111\",\"data\":{\"current\":64,\"total\":128,\"unit\":\"MiB\"}}\n"
	if output.String() != want {
		t.Fatalf("unexpected JSON\nwant: %s\n got: %s", want, output.String())
	}
}

func TestRendererUsesOneWriteAfterCompleteEncoding(t *testing.T) {
	t.Parallel()
	writer := &countingWriter{}
	if err := NewRenderer(true).Success(writer, CodeAcknowledged, AcknowledgementPayload{Message: "done"}); err != nil {
		t.Fatalf("render acknowledgement: %v", err)
	}
	if writer.calls != 1 {
		t.Fatalf("writes = %d, want exactly one", writer.calls)
	}
	if strings.Count(writer.output.String(), "\n") != 1 || !strings.HasSuffix(writer.output.String(), "\n") {
		t.Fatalf("machine output is not one newline-terminated record: %q", writer.output.String())
	}
}

func TestRendererRejectsOversizedOutputBeforeWrite(t *testing.T) {
	t.Parallel()
	writer := &countingWriter{}
	err := NewBoundedRenderer(true, 32).Success(writer, CodeAcknowledged, AcknowledgementPayload{Message: strings.Repeat("x", 64)})
	assertRenderFailure(t, err)
	if writer.calls != 0 || writer.output.Len() != 0 {
		t.Fatalf("oversized record reached writer: calls=%d output=%q", writer.calls, writer.output.String())
	}
}

func TestRendererNormalizesPartialWrite(t *testing.T) {
	t.Parallel()
	err := NewRenderer(true).Success(shortWriter{}, CodeAcknowledged, AcknowledgementPayload{Message: "done"})
	assertRenderFailure(t, err)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error does not retain short-write cause for internal handling: %v", err)
	}
}

func TestRendererNormalizesEncodingFailureWithoutLeakingCause(t *testing.T) {
	t.Parallel()
	const secret = "ENCODER-DETAIL-MUST-NOT-APPEAR"
	data := StateChangePayload{
		State: "RUNNING", Message: secret,
		// encoding/json rejects time values outside the RFC 3339 year range.
		Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	var output bytes.Buffer
	err := NewRenderer(true).Event(&output, "SESSION_STATE_CHANGED", 1, "", data)
	assertRenderFailure(t, err)
	if output.Len() != 0 {
		t.Fatalf("encoding failure emitted partial JSON: %q", output.String())
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("safe render error exposed encoding input: %q", err.Error())
	}

	var normalized bytes.Buffer
	if secondErr := NewRenderer(true).Error(&normalized, err); secondErr != nil {
		t.Fatalf("render normalized error: %v", secondErr)
	}
	if strings.Contains(normalized.String(), secret) || strings.Contains(normalized.String(), "year outside") {
		t.Fatalf("normalized error serialized its wrapped cause: %q", normalized.String())
	}
}

func TestRendererNormalizesWriterFailureWithoutLeakingCause(t *testing.T) {
	t.Parallel()
	const secret = "WRITER-DETAIL-MUST-NOT-APPEAR"
	err := NewRenderer(false).Success(errorWriter{err: errors.New(secret)}, CodeAcknowledged, AcknowledgementPayload{Message: "done"})
	assertRenderFailure(t, err)
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("safe render error exposed writer cause: %q", err.Error())
	}

	var output bytes.Buffer
	if secondErr := NewRenderer(true).Error(&output, err); secondErr != nil {
		t.Fatalf("render normalized error: %v", secondErr)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("normalized error serialized writer cause: %q", output.String())
	}
}

func TestHumanRendererSanitizesControlCharactersAndOmitsCause(t *testing.T) {
	t.Parallel()
	const secret = "PRIVATE-KEY-MUST-NOT-APPEAR"
	app := apperror.Wrap(
		"CONFIG_INVALID", exitcode.Configuration, "bad\nforged: entry", "fix\rthe\tfield",
		errors.New(secret),
	)
	var output bytes.Buffer

	if err := NewRenderer(false).Error(&output, app); err != nil {
		t.Fatalf("render human error: %v", err)
	}
	want := "CONFIG_INVALID: bad forged: entry\nremediation: fix the field\n"
	if output.String() != want {
		t.Fatalf("unexpected human output\nwant: %q\n got: %q", want, output.String())
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("human output exposed wrapped cause")
	}
}

func TestMalformedApplicationErrorIsNormalized(t *testing.T) {
	t.Parallel()
	malformed := apperror.New("bad code", 99, "unsafe internal detail", "unsafe remediation")
	var output bytes.Buffer
	if err := NewRenderer(true).Error(&output, malformed); err != nil {
		t.Fatalf("render malformed error: %v", err)
	}
	want := "{\"schema_version\":1,\"ok\":false,\"code\":\"INTERNAL_ERROR\",\"exit_code\":70,\"message\":\"An internal error occurred.\",\"remediation\":\"Retry once; if the error persists, export a redacted diagnostic bundle.\"}\n"
	if output.String() != want {
		t.Fatalf("unexpected normalized error\nwant: %s\n got: %s", want, output.String())
	}
}

func TestInvalidEventFailsBeforeWrite(t *testing.T) {
	t.Parallel()
	writer := &countingWriter{}
	err := NewRenderer(true).Event(writer, "bad-code", 0, "", ProgressPayload{})
	assertRenderFailure(t, err)
	if writer.calls != 0 {
		t.Fatalf("invalid event reached writer %d times", writer.calls)
	}
}

func TestMismatchedSuccessCodeFailsBeforeWrite(t *testing.T) {
	t.Parallel()
	writer := &countingWriter{}
	err := NewRenderer(true).Success(writer, CodeDoctorReport, VersionPayload{Version: "1.0.0"})
	assertRenderFailure(t, err)
	if writer.calls != 0 {
		t.Fatalf("mismatched success record reached writer %d times", writer.calls)
	}
}

type countingWriter struct {
	calls  int
	output bytes.Buffer
}

func (writer *countingWriter) Write(value []byte) (int, error) {
	writer.calls++
	return writer.output.Write(value)
}

type shortWriter struct{}

func (shortWriter) Write(value []byte) (int, error) {
	return len(value) - 1, nil
}

type errorWriter struct{ err error }

func (writer errorWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

func assertRenderFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected render failure")
	}
	var app *apperror.Error
	if !errors.As(err, &app) {
		t.Fatalf("error type = %T, want *apperror.Error", err)
	}
	if app.Code != string(CodeRenderFailed) || app.ExitCode != exitcode.Internal {
		t.Fatalf("error = %#v, want OUTPUT_RENDER_FAILED/70", app)
	}
}
