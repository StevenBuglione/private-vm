package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePDFDocumentEvidenceCoversEveryPageAndReportsMaximums(t *testing.T) {
	evidence, err := parsePDFDocumentEvidence([]byte("" +
		"Pages:           3\n" +
		"Page    1 size:  612 x 792 pts (letter)\n" +
		"Page    2 size:  1400.25 x 500 pts\n" +
		"Page    3 size:  800 x 2000.01 pts\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Complete || evidence.Pages != 3 || evidence.MaximumWidth != 1401 || evidence.MaximumHeight != 2001 {
		t.Fatalf("evidence = %#v", evidence)
	}

	single, err := parsePDFDocumentEvidence([]byte("Pages: 1\nPage    1 size: 612.1 x 792.1 pts (letter)\n"))
	if err != nil || !single.Complete || single.Pages != 1 || single.MaximumWidth != 613 || single.MaximumHeight != 793 {
		t.Fatalf("single-page evidence = %#v, %v", single, err)
	}
}

func TestParsePDFDocumentEvidenceExposesOversizedLaterPageToPolicy(t *testing.T) {
	evidence, err := parsePDFDocumentEvidence([]byte("" +
		"Pages: 2\n" +
		"Page 1 size: 612 x 792 pts\n" +
		"Page 2 size: 40000 x 500 pts\n"))
	if err != nil {
		t.Fatal(err)
	}
	if evidence.MaximumWidth != 40000 {
		t.Fatalf("evidence = %#v", evidence)
	}
	if validDocumentEvidence(evidence, ReconstructionLimits{MaxDocumentPages: 2000, MaxDimension: 32768}) {
		t.Fatal("oversized later page passed the document policy")
	}
}

func TestParsePDFDocumentEvidenceRejectsMissingDuplicateOutOfRangeAndInconsistentRecords(t *testing.T) {
	tests := map[string]string{
		"missing-page":        "Pages: 3\nPage 1 size: 10 x 20 pts\nPage 2 size: 10 x 20 pts\n",
		"duplicate-page":      "Pages: 2\nPage 1 size: 10 x 20 pts\nPage 1 size: 30 x 40 pts\n",
		"out-of-range-page":   "Pages: 2\nPage 1 size: 10 x 20 pts\nPage 3 size: 30 x 40 pts\n",
		"duplicate-count":     "Pages: 2\nPages: 2\nPage 1 size: 10 x 20 pts\nPage 2 size: 30 x 40 pts\n",
		"generic-multi-page":  "Pages: 2\nPage size: 10 x 20 pts\n",
		"generic-single-page": "Pages: 1\nPage size: 10 x 20 pts\n",
		"unsupported-count":   "Pages: 10001\n",
		"zero-dimension":      "Pages: 1\nPage 1 size: 0 x 20 pts\n",
		"too-large-dimension": "Pages: 1\nPage 1 size: 4294967296 x 20 pts\n",
	}
	for name, output := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePDFDocumentEvidence([]byte(output)); ErrorCode(err) != "SANITIZER_FAILED" {
				t.Fatalf("error = %v (%s)", err, ErrorCode(err))
			}
		})
	}
}

func TestCommandDocumentProbeUsesBoundedAllPageStdinContract(t *testing.T) {
	script := writePDFProbeScript(t, `
if [ "$#" -ne 5 ] || [ "$1" != "-f" ] || [ "$2" != "1" ] || [ "$3" != "-l" ] || [ "$4" != "10000" ] || [ "$5" != "-" ]; then
  exit 81
fi
IFS= read -r first
if [ "$first" != "%PDF-hostile-name /tmp/must-not-enter-argv.pdf" ]; then
  exit 82
fi
printf 'Pages: 2\nPage    1 size: 10 x 20 pts\nPage    2 size: 300.5 x 400.5 pts\n'
`)
	probe := CommandDocumentProbe{executable: script, tool: ToolEvidence{Name: "poppler-pdfinfo", Version: "test-version"}}
	evidence, tool, err := probe.ProbeDocument(t.Context(), strings.NewReader("%PDF-hostile-name /tmp/must-not-enter-argv.pdf\npayload"))
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Pages != 2 || evidence.MaximumWidth != 301 || evidence.MaximumHeight != 401 || tool.Name != "poppler-pdfinfo" {
		t.Fatalf("evidence=%#v tool=%#v", evidence, tool)
	}
}

func TestCommandDocumentProbePreservesCancellationTimeoutAndOutputBound(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		probe := CommandDocumentProbe{executable: writePDFProbeScript(t, "printf 'Pages: 1\\nPage size: 1 x 1 pts\\n'\n"), tool: ToolEvidence{Name: "poppler-pdfinfo", Version: "test-version"}}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, _, err := probe.ProbeDocument(ctx, strings.NewReader("pdf")); ErrorCode(err) != "SCAN_CANCELLED" {
			t.Fatalf("error = %v (%s)", err, ErrorCode(err))
		}
	})

	t.Run("timeout", func(t *testing.T) {
		probe := CommandDocumentProbe{executable: writePDFProbeScript(t, "while :; do :; done\n"), tool: ToolEvidence{Name: "poppler-pdfinfo", Version: "test-version"}}
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		if _, _, err := probe.ProbeDocument(ctx, strings.NewReader("pdf")); ErrorCode(err) != "SCAN_TIMEOUT" {
			t.Fatalf("error = %v (%s)", err, ErrorCode(err))
		}
	})

	t.Run("stdout-bound", func(t *testing.T) {
		chunk := strings.Repeat("x", 1024)
		script := "chunk='" + chunk + "'\ni=0\nwhile [ \"$i\" -lt 1025 ]; do printf '%s' \"$chunk\"; i=$((i + 1)); done\n"
		probe := CommandDocumentProbe{executable: writePDFProbeScript(t, script), tool: ToolEvidence{Name: "poppler-pdfinfo", Version: "test-version"}}
		if _, _, err := probe.ProbeDocument(t.Context(), strings.NewReader("pdf")); ErrorCode(err) != "SANITIZER_FAILED" {
			t.Fatalf("error = %v (%s)", err, ErrorCode(err))
		}
	})
}

func writePDFProbeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pdfinfo-fixture")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
