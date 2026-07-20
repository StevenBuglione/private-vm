//go:build linux

package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/policy"
)

type transformerFunc func(context.Context, io.ReadSeeker, io.Writer, uint64) (ToolEvidence, error)

func (function transformerFunc) Transform(ctx context.Context, input io.ReadSeeker, output io.Writer, limit uint64) (ToolEvidence, error) {
	return function(ctx, input, output, limit)
}

type documentProbeFunc func(context.Context, io.ReadSeeker) (DocumentEvidence, ToolEvidence, error)

func (function documentProbeFunc) ProbeDocument(ctx context.Context, input io.ReadSeeker) (DocumentEvidence, ToolEvidence, error) {
	return function(ctx, input)
}

func TestReconstructPDFVerifiesNewOutputRescanAndCleanup(t *testing.T) {
	input, entry := reconstructionInput(t, []byte("%PDF-original"), "application/pdf")
	defer input.Close()
	sandbox := reconstructionSandbox(t)
	probeCalls := 0
	reconstructor := testReconstructor(t, sandbox)
	reconstructor.PDF = transformerFunc(func(_ context.Context, _ io.ReadSeeker, output io.Writer, _ uint64) (ToolEvidence, error) {
		_, err := io.WriteString(output, "%PDF-rasterized-new")
		return ToolEvidence{Name: "pdf-raster", Version: "1"}, err
	})
	reconstructor.DocumentProbe = documentProbeFunc(func(context.Context, io.ReadSeeker) (DocumentEvidence, ToolEvidence, error) {
		probeCalls++
		return DocumentEvidence{Pages: 2, MaximumWidth: 1000, MaximumHeight: 1000, Complete: true}, ToolEvidence{Name: "pdf-probe", Version: "1"}, nil
	})
	output, err := reconstructor.Reconstruct(t.Context(), input, entry)
	if err != nil {
		t.Fatal(err)
	}
	if probeCalls != 2 || output.DetectedMIME != "application/pdf" || output.Transformation != "pdf-raster-rebuild-v1" || len(output.Tools) != 3 || output.SHA256 == entry.SHA256 {
		t.Fatalf("output = %+v, probe calls = %d", output, probeCalls)
	}
	reader, err := output.Open()
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || string(content) != "%PDF-rasterized-new" {
		t.Fatalf("content = %q, error = %v", content, err)
	}
	if err := output.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := output.Cleanup(); err != nil {
		t.Fatalf("idempotent cleanup: %v", err)
	}
}

func TestOfficeUsesRenderThenRasterPipeline(t *testing.T) {
	input, entry := reconstructionInput(t, []byte("office-input"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	defer input.Close()
	reconstructor := testReconstructor(t, reconstructionSandbox(t))
	reconstructor.OfficeRenderer = transformerFunc(func(_ context.Context, _ io.ReadSeeker, output io.Writer, _ uint64) (ToolEvidence, error) {
		_, err := io.WriteString(output, "%PDF-rendered-office")
		return ToolEvidence{Name: "libreoffice", Version: "1"}, err
	})
	reconstructor.PDF = transformerFunc(func(_ context.Context, input io.ReadSeeker, output io.Writer, _ uint64) (ToolEvidence, error) {
		body, _ := io.ReadAll(input)
		if string(body) != "%PDF-rendered-office" {
			return ToolEvidence{}, errors.New("wrong intermediate")
		}
		_, err := io.WriteString(output, "%PDF-rasterized-office")
		return ToolEvidence{Name: "pdf-raster", Version: "1"}, err
	})
	reconstructor.DocumentProbe = documentProbeFunc(func(context.Context, io.ReadSeeker) (DocumentEvidence, ToolEvidence, error) {
		return DocumentEvidence{Pages: 1, MaximumWidth: 1000, MaximumHeight: 1000, Complete: true}, ToolEvidence{Name: "pdf-probe", Version: "1"}, nil
	})
	output, err := reconstructor.Reconstruct(t.Context(), input, entry)
	if err != nil {
		t.Fatal(err)
	}
	if output.Transformation != "office-render-pdf-raster-rebuild-v1" || len(output.Tools) != 4 {
		t.Fatalf("output = %+v", output)
	}
	if err := output.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestImageDecodeAndReencodeStripsOriginalBytes(t *testing.T) {
	var encoded bytes.Buffer
	pixels := image.NewRGBA(image.Rect(0, 0, 2, 2))
	pixels.Set(0, 0, color.RGBA{R: 255, A: 255})
	if err := jpeg.Encode(&encoded, pixels, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
	input, entry := reconstructionInput(t, encoded.Bytes(), "image/jpeg")
	defer input.Close()
	reconstructor := testReconstructor(t, reconstructionSandbox(t))
	output, err := reconstructor.Reconstruct(t.Context(), input, entry)
	if err != nil {
		t.Fatal(err)
	}
	if output.DetectedMIME != "image/png" || output.Transformation != "image-decode-strip-reencode-png-v1" {
		t.Fatalf("output = %+v", output)
	}
	if err := output.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestReconstructionFailsClosedAndCleansPartialOutput(t *testing.T) {
	tests := []struct {
		name      string
		mime      string
		configure func(*Reconstructor, []byte)
		code      string
	}{
		{"active", "application/x-executable", func(*Reconstructor, []byte) {}, "ACTIVE_CONTENT_BLOCKED"},
		{"unsupported", "application/octet-stream", func(*Reconstructor, []byte) {}, "SANITIZER_UNSUPPORTED_TYPE"},
		{"missing", "application/pdf", func(*Reconstructor, []byte) {}, "SANITIZER_UNAVAILABLE"},
		{"tool failure", "application/pdf", func(r *Reconstructor, _ []byte) {
			r.PDF = transformerFunc(func(context.Context, io.ReadSeeker, io.Writer, uint64) (ToolEvidence, error) {
				return ToolEvidence{}, scanError("SANITIZER_FAILED", "failed", "reject", nil)
			})
			r.DocumentProbe = validDocumentProbe()
		}, "SANITIZER_FAILED"},
		{"unchanged", "application/pdf", func(r *Reconstructor, source []byte) {
			r.PDF = transformerFunc(func(_ context.Context, _ io.ReadSeeker, output io.Writer, _ uint64) (ToolEvidence, error) {
				_, err := output.Write(source)
				return ToolEvidence{Name: "fake", Version: "1"}, err
			})
			r.DocumentProbe = validDocumentProbe()
		}, "SANITIZED_OUTPUT_INVALID"},
		{"rescan finding", "application/pdf", func(r *Reconstructor, _ []byte) {
			r.PDF = fixedTransformer("%PDF-new")
			r.DocumentProbe = validDocumentProbe()
			r.Rescanner = scannerFunc(func(context.Context, io.Reader, uint64) (ClamResult, error) {
				return ClamResult{Finding: Finding{Code: "MALWARE_DETECTED", Severity: SeverityBlocking, Detail: "blocked"}}, nil
			})
		}, "SANITIZED_OUTPUT_REJECTED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sandbox := reconstructionSandbox(t)
			source := []byte("%PDF-source")
			input, entry := reconstructionInput(t, source, test.mime)
			defer input.Close()
			reconstructor := testReconstructor(t, sandbox)
			test.configure(&reconstructor, source)
			_, err := reconstructor.Reconstruct(t.Context(), input, entry)
			if ErrorCode(err) != test.code {
				t.Fatalf("error = %v", err)
			}
			entries, readErr := os.ReadDir(sandbox.ParentPath)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("partial output remains: %v, %v", entries, readErr)
			}
		})
	}
}

func TestCommandTransformerUsesStdinStdoutBoundsAndCancellation(t *testing.T) {
	catPath, err := filepath.EvalSymlinks("/bin/cat")
	if err != nil {
		t.Skip(err)
	}
	transformer, err := NewCommandTransformer(catPath, nil, ToolEvidence{Name: "cat-fixture", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	tool, err := transformer.Transform(t.Context(), strings.NewReader("fixture"), &output, 32)
	if err != nil || output.String() != "fixture" || !tool.valid() {
		t.Fatalf("output = %q, tool = %+v, error = %v", output.String(), tool, err)
	}
	if _, err := transformer.Transform(t.Context(), strings.NewReader("too large"), io.Discard, 3); ErrorCode(err) != "SCAN_LIMIT_REACHED" {
		t.Fatalf("limit error = %v", err)
	}

	sleepPath, err := filepath.EvalSymlinks("/bin/sleep")
	if err == nil {
		sleeper, createErr := NewCommandTransformer(sleepPath, []string{"1"}, ToolEvidence{Name: "sleep-fixture", Version: "1"})
		if createErr != nil {
			t.Fatal(createErr)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Millisecond)
		defer cancel()
		if _, err := sleeper.Transform(ctx, strings.NewReader(""), io.Discard, 1); ErrorCode(err) != "SCAN_TIMEOUT" {
			t.Fatalf("timeout error = %v", err)
		}
	}
	if _, err := NewCommandTransformer(catPath, []string{"/user/file"}, ToolEvidence{Name: "cat", Version: "1"}); ErrorCode(err) != "SANITIZER_CONFIG_INVALID" {
		t.Fatalf("filename argument error = %v", err)
	}
}

func TestReconstructionCancellationRemovesPartialOutput(t *testing.T) {
	sandbox := reconstructionSandbox(t)
	input, entry := reconstructionInput(t, []byte("%PDF-source"), "application/pdf")
	defer input.Close()
	reconstructor := testReconstructor(t, sandbox)
	reconstructor.DocumentProbe = validDocumentProbe()
	ctx, cancel := context.WithCancel(t.Context())
	reconstructor.PDF = transformerFunc(func(ctx context.Context, _ io.ReadSeeker, output io.Writer, _ uint64) (ToolEvidence, error) {
		_, _ = io.WriteString(output, "%PDF-partial")
		cancel()
		<-ctx.Done()
		return ToolEvidence{}, contextScanError(ctx.Err())
	})
	_, err := reconstructor.Reconstruct(ctx, input, entry)
	if ErrorCode(err) != "SCAN_CANCELLED" {
		t.Fatalf("cancellation error = %v", err)
	}
	entries, readErr := os.ReadDir(sandbox.ParentPath)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("cancellation left output: %v, %v", entries, readErr)
	}
}

func fixedTransformer(value string) Transformer {
	return transformerFunc(func(_ context.Context, _ io.ReadSeeker, output io.Writer, _ uint64) (ToolEvidence, error) {
		_, err := io.WriteString(output, value)
		return ToolEvidence{Name: "fixed", Version: "1"}, err
	})
}

func validDocumentProbe() DocumentProbe {
	return documentProbeFunc(func(context.Context, io.ReadSeeker) (DocumentEvidence, ToolEvidence, error) {
		return DocumentEvidence{Pages: 1, MaximumWidth: 100, MaximumHeight: 100, Complete: true}, ToolEvidence{Name: "probe", Version: "1"}, nil
	})
}

func testReconstructor(t *testing.T, sandbox ExtractionSandbox) Reconstructor {
	t.Helper()
	policyFile, err := os.Open(filepath.Join("..", "..", "examples", "policy.safe.toml"))
	if err != nil {
		t.Fatal(err)
	}
	safePolicy, err := policy.Decode(policyFile)
	policyFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	return Reconstructor{
		Policy: safePolicy, Sandbox: sandbox, Classifier: ConservativeMIMEClassifier{},
		Rescanner: scannerFunc(func(_ context.Context, input io.Reader, size uint64) (ClamResult, error) {
			count, err := io.Copy(io.Discard, input)
			if err != nil || uint64(count) != size {
				return ClamResult{}, errors.New("rescan incomplete")
			}
			return ClamResult{Clean: true, Finding: Finding{Code: "CLAMAV_CLEAN", Severity: SeverityInfo, Detail: "complete"}}, nil
		}),
		Limits: ReconstructionLimits{
			MaxOutputBytes: 1 << 20, MaxImagePixels: 1_000_000, MaxDocumentPages: 100,
			MaxDimension: 10000, MaxMediaDuration: 3600, MaxMediaStreams: 8, MaxTextBytes: 1 << 20,
		},
	}
}

func reconstructionSandbox(t *testing.T) ExtractionSandbox {
	root := runtimeTmpfs(t)
	return ExtractionSandbox{ParentPath: root, Tmpfs: true, PrivateMountNamespace: true, WorkerUID: os.Geteuid(), WorkerGID: os.Getegid()}
}

func reconstructionInput(t *testing.T, content []byte, mime string) (*os.File, InventoryEntry) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "input-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return file, InventoryEntry{RelativePath: "input", SizeBytes: uint64(len(content)), SHA256: hex.EncodeToString(digest[:]), DetectedMIME: mime}
}
