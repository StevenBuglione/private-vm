package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maximumProbeOutputBytes    = 256 << 10
	maximumPDFProbeOutputBytes = 1 << 20
	maximumPDFProbePages       = 10000
)

// CommandMIMEClassifier invokes the pinned file(1) build with the bounded
// prefix on stdin. No hostile path or logical name crosses the process API.
type CommandMIMEClassifier struct{ executable string }

func NewCommandMIMEClassifier(executable string) (CommandMIMEClassifier, error) {
	resolved, err := trustedExecutable(executable)
	if err != nil {
		return CommandMIMEClassifier{}, err
	}
	return CommandMIMEClassifier{executable: resolved}, nil
}

func (classifier CommandMIMEClassifier) Classify(ctx context.Context, prefix []byte) (string, error) {
	if classifier.executable == "" || len(prefix) > 1<<20 {
		return "", scanError("SCAN_CLASSIFIER_UNAVAILABLE", "The content classifier is unavailable.", "Reinstall the verified scanner image and retry.", nil)
	}
	output, err := runBoundedCommand(ctx, classifier.executable, []string{"--brief", "--mime-type", "-"}, bytes.NewReader(prefix), 1024, nil)
	if err != nil {
		return "", scanError("SCAN_TYPE_IDENTIFICATION_FAILED", "The pinned content classifier did not complete.", "Reject the quarantine and retry with the verified scanner image.", err)
	}
	value := strings.TrimSpace(string(output))
	clear(output)
	if !validMIME(value) {
		return "", scanError("SCAN_TYPE_IDENTIFICATION_FAILED", "The pinned content classifier returned an invalid type.", "Reject the quarantine and retry with the verified scanner image.", nil)
	}
	return value, nil
}

type CommandDocumentProbe struct {
	executable string
	tool       ToolEvidence
}

func NewCommandDocumentProbe(executable, version string) (CommandDocumentProbe, error) {
	resolved, err := trustedExecutable(executable)
	tool := ToolEvidence{Name: "poppler-pdfinfo", Version: version}
	if err != nil || !tool.valid() {
		return CommandDocumentProbe{}, scanError("SANITIZER_CONFIG_INVALID", "The PDF probe is unavailable.", "Reinstall the verified scanner image and retry.", err)
	}
	return CommandDocumentProbe{executable: resolved, tool: tool}, nil
}

var (
	pdfPagesPattern       = regexp.MustCompile(`(?m)^Pages:\s+([0-9]+)\s*$`)
	pdfIndexedSizePattern = regexp.MustCompile(`(?m)^Page\s+([0-9]+)\s+size:\s+([0-9]+(?:\.[0-9]+)?) x ([0-9]+(?:\.[0-9]+)?) pts(?:\s|$)`)
)

func (probe CommandDocumentProbe) ProbeDocument(ctx context.Context, input io.ReadSeeker) (DocumentEvidence, ToolEvidence, error) {
	if probe.executable == "" || input == nil {
		return DocumentEvidence{}, ToolEvidence{}, missingBackendError()
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return DocumentEvidence{}, ToolEvidence{}, scanError("SANITIZER_FAILED", "The document could not be rewound for its bounded probe.", "Reject the document and destroy the scanner.", err)
	}
	// Asking for the complete supported page range makes pdfinfo emit one
	// indexed size record for every page. A document
	// above the hard ceiling still reports its larger total and is rejected.
	// Content remains on stdin; no hostile pathname enters argv.
	output, err := runBoundedCommand(ctx, probe.executable, []string{"-f", "1", "-l", strconv.Itoa(maximumPDFProbePages), "-"}, input, maximumPDFProbeOutputBytes, nil)
	if err != nil {
		if ctx.Err() != nil {
			return DocumentEvidence{}, ToolEvidence{}, contextScanError(ctx.Err())
		}
		return DocumentEvidence{}, ToolEvidence{}, scanError("SANITIZER_FAILED", "The bounded PDF probe did not complete.", "Reject the document and destroy the scanner.", err)
	}
	defer clear(output)
	evidence, err := parsePDFDocumentEvidence(output)
	if err != nil {
		return DocumentEvidence{}, ToolEvidence{}, err
	}
	return evidence, probe.tool, nil
}

func parsePDFDocumentEvidence(output []byte) (DocumentEvidence, error) {
	pageCounts := pdfPagesPattern.FindAllSubmatch(output, -1)
	if len(pageCounts) != 1 || len(pageCounts[0]) != 2 {
		return DocumentEvidence{}, incompletePDFEvidenceError()
	}
	pageCount, err := strconv.ParseUint(string(pageCounts[0][1]), 10, 32)
	if err != nil || pageCount == 0 || pageCount > maximumPDFProbePages {
		return DocumentEvidence{}, invalidPDFEvidenceError()
	}

	indexedSizes := pdfIndexedSizePattern.FindAllSubmatch(output, -1)
	if uint64(len(indexedSizes)) != pageCount {
		return DocumentEvidence{}, incompletePDFEvidenceError()
	}

	seen := make([]bool, int(pageCount))
	evidence := DocumentEvidence{Pages: uint32(pageCount), Complete: true}
	for _, match := range indexedSizes {
		if len(match) != 4 {
			return DocumentEvidence{}, incompletePDFEvidenceError()
		}
		page, pageErr := strconv.ParseUint(string(match[1]), 10, 32)
		width, height, dimensionsOK := parsePDFDimensions(match[2], match[3])
		if pageErr != nil || page == 0 || page > pageCount || seen[page-1] || !dimensionsOK {
			return DocumentEvidence{}, invalidPDFEvidenceError()
		}
		seen[page-1] = true
		if width > evidence.MaximumWidth {
			evidence.MaximumWidth = width
		}
		if height > evidence.MaximumHeight {
			evidence.MaximumHeight = height
		}
	}
	for _, present := range seen {
		if !present {
			return DocumentEvidence{}, incompletePDFEvidenceError()
		}
	}
	return evidence, nil
}

func parsePDFDimensions(widthBytes, heightBytes []byte) (uint32, uint32, bool) {
	width, widthErr := strconv.ParseFloat(string(widthBytes), 64)
	height, heightErr := strconv.ParseFloat(string(heightBytes), 64)
	if widthErr != nil || heightErr != nil || width <= 0 || height <= 0 || math.IsNaN(width) || math.IsNaN(height) ||
		math.IsInf(width, 0) || math.IsInf(height, 0) || width > math.MaxUint32 || height > math.MaxUint32 {
		return 0, 0, false
	}
	return uint32(math.Ceil(width)), uint32(math.Ceil(height)), true
}

func incompletePDFEvidenceError() error {
	return scanError("SANITIZER_FAILED", "The PDF probe returned incomplete all-page structure evidence.", "Reject the document and destroy the scanner.", nil)
}

func invalidPDFEvidenceError() error {
	return scanError("SANITIZER_FAILED", "The PDF probe returned invalid all-page structure evidence.", "Reject the document and destroy the scanner.", nil)
}

type CommandMediaProbe struct {
	executable string
	tool       ToolEvidence
}

func NewCommandMediaProbe(executable, version string) (CommandMediaProbe, error) {
	resolved, err := trustedExecutable(executable)
	tool := ToolEvidence{Name: "ffprobe-json", Version: version}
	if err != nil || !tool.valid() {
		return CommandMediaProbe{}, scanError("SANITIZER_CONFIG_INVALID", "The media probe is unavailable.", "Reinstall the verified scanner image and retry.", err)
	}
	return CommandMediaProbe{executable: resolved, tool: tool}, nil
}

type ffprobeEnvelope struct {
	Streams []struct {
		CodecType string `json:"codec_type"`
		Width     uint32 `json:"width"`
		Height    uint32 `json:"height"`
	} `json:"streams"`
	Chapters []json.RawMessage `json:"chapters"`
	Format   struct {
		Duration string `json:"duration"`
	} `json:"format"`
}

func (probe CommandMediaProbe) ProbeMedia(ctx context.Context, input io.ReadSeeker) (MediaEvidence, ToolEvidence, error) {
	if probe.executable == "" || input == nil {
		return MediaEvidence{}, ToolEvidence{}, missingBackendError()
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return MediaEvidence{}, ToolEvidence{}, scanError("SANITIZER_FAILED", "The media input could not be rewound for its bounded probe.", "Reject the media and destroy the scanner.", err)
	}
	arguments := []string{
		"-v", "error", "-show_entries", "format=duration:stream=codec_type,width,height:chapter=id",
		"-of", "json", "pipe:0",
	}
	output, err := runBoundedCommand(ctx, probe.executable, arguments, input, maximumProbeOutputBytes, nil)
	if err != nil {
		return MediaEvidence{}, ToolEvidence{}, scanError("SANITIZER_FAILED", "The bounded media probe did not complete.", "Reject the media and destroy the scanner.", err)
	}
	defer clear(output)
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var envelope ffprobeEnvelope
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF || len(envelope.Streams) == 0 {
		return MediaEvidence{}, ToolEvidence{}, scanError("SANITIZER_FAILED", "The media probe returned invalid structure evidence.", "Reject the media and destroy the scanner.", err)
	}
	duration, err := strconv.ParseFloat(envelope.Format.Duration, 64)
	if err != nil || duration <= 0 || math.IsNaN(duration) || math.IsInf(duration, 0) || duration > math.MaxUint64 {
		return MediaEvidence{}, ToolEvidence{}, scanError("SANITIZER_FAILED", "The media duration evidence is invalid.", "Reject the media and destroy the scanner.", err)
	}
	evidence := MediaEvidence{DurationSeconds: uint64(math.Ceil(duration)), Streams: uint32(len(envelope.Streams)), Chapters: uint32(len(envelope.Chapters)), Complete: true}
	for _, stream := range envelope.Streams {
		if stream.CodecType == "attachment" {
			evidence.Attachments++
		}
		if stream.Width > evidence.MaximumWidth {
			evidence.MaximumWidth = stream.Width
		}
		if stream.Height > evidence.MaximumHeight {
			evidence.MaximumHeight = stream.Height
		}
	}
	return evidence, probe.tool, nil
}

// LibreOfficeTransformer uses only scanner-generated opaque paths inside a
// verified tmpfs. Hostile logical names never enter argv, the environment or
// the filesystem. The guestd service itself supplies the unprivileged private
// mount namespace and offline network boundary.
type LibreOfficeTransformer struct {
	executable string
	parent     string
	tool       ToolEvidence
}

func NewLibreOfficeTransformer(executable, version, parent string) (LibreOfficeTransformer, error) {
	resolved, err := trustedExecutable(executable)
	tool := ToolEvidence{Name: "libreoffice-headless-pdf", Version: version}
	if err != nil || !tool.valid() || !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		return LibreOfficeTransformer{}, scanError("SANITIZER_CONFIG_INVALID", "The Office renderer is unavailable.", "Reinstall the verified scanner image and retry.", err)
	}
	return LibreOfficeTransformer{executable: resolved, parent: parent, tool: tool}, nil
}

func (transformer LibreOfficeTransformer) Transform(ctx context.Context, input io.ReadSeeker, output io.Writer, maximumOutput uint64) (ToolEvidence, error) {
	if transformer.executable == "" || input == nil || output == nil || maximumOutput == 0 || maximumOutput > 4<<40 ||
		os.Geteuid() <= 0 || !extractionParentIsTmpfs(transformer.parent) {
		return ToolEvidence{}, scanError("SANITIZER_SANDBOX_UNVERIFIED", "The Office renderer is not in its verified unprivileged tmpfs.", "Destroy the scanner and retry with the verified scanner image.", nil)
	}
	directory, err := os.MkdirTemp(transformer.parent, "private-vm-office-")
	if err != nil {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The Office renderer could not create volatile input storage.", "Destroy the scanner and retry.", err)
	}
	defer os.RemoveAll(directory)
	inputFile, err := os.CreateTemp(directory, "private-vm-office-input-")
	if err != nil {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The Office renderer could not create its opaque input.", "Destroy the scanner and retry.", err)
	}
	inputPath := inputFile.Name()
	if err := inputFile.Chmod(0o600); err != nil {
		inputFile.Close()
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The Office renderer could not protect its opaque input.", "Destroy the scanner and retry.", err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		inputFile.Close()
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The Office input could not be rewound.", "Reject the document and destroy the scanner.", err)
	}
	written, copyErr := io.CopyBuffer(inputFile, io.LimitReader(&contextReader{ctx: ctx, reader: input}, int64(maximumOutput)+1), make([]byte, 1<<20))
	if copyErr != nil || written <= 0 || uint64(written) > maximumOutput {
		inputFile.Close()
		return ToolEvidence{}, scanError("SCAN_LIMIT_REACHED", "The Office input exceeds the renderer bound.", "Reduce the document size and retry.", copyErr)
	}
	if _, err := inputFile.Seek(0, io.SeekStart); err != nil {
		inputFile.Close()
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The Office input could not be rewound.", "Reject the document and destroy the scanner.", err)
	}
	if err := os.Remove(inputPath); err != nil {
		inputFile.Close()
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The Office input name could not be removed before parsing.", "Destroy the scanner and retry.", err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		inputFile.Close()
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The Office output directory could not be opened safely.", "Destroy the scanner and retry.", err)
	}
	arguments := []string{
		"--headless", "--nologo", "--nodefault", "--nolockcheck", "--norestore", "--convert-to", "pdf",
		"--outdir", "/proc/self/fd/4", "/proc/self/fd/3",
	}
	command := exec.CommandContext(ctx, transformer.executable, arguments...)
	command.Env = []string{"HOME=/run/private-vm", "LANG=C.UTF-8", "SAL_USE_VCLPLUGIN=svp"}
	command.ExtraFiles = []*os.File{inputFile, directoryFile}
	var commandOutput boundedCommandBuffer
	commandOutput.remaining = 64 << 10
	command.Stdout = &commandOutput
	command.Stderr = io.Discard
	runErr := command.Run()
	closeInputErr := inputFile.Close()
	closeDirectoryErr := directoryFile.Close()
	clear(commandOutput.buffer.Bytes())
	if runErr != nil || closeInputErr != nil || closeDirectoryErr != nil || commandOutput.exceeded {
		if ctx.Err() != nil {
			return ToolEvidence{}, contextScanError(ctx.Err())
		}
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The Office renderer did not complete.", "Reject the document and destroy the scanner.", errors.Join(runErr, closeInputErr, closeDirectoryErr))
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].IsDir() || filepath.Ext(entries[0].Name()) != ".pdf" || filepath.Base(entries[0].Name()) != entries[0].Name() {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The Office renderer did not produce its expected PDF.", "Reject the document and destroy the scanner.", err)
	}
	resultPath := filepath.Join(directory, entries[0].Name())
	fd, err := unix.Open(resultPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The Office PDF could not be opened safely.", "Reject the document and destroy the scanner.", err)
	}
	result := os.NewFile(uintptr(fd), "office-pdf")
	if result == nil {
		unix.Close(fd)
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The Office PDF descriptor is invalid.", "Reject the document and destroy the scanner.", nil)
	}
	defer result.Close()
	count, err := io.CopyBuffer(&boundedTransformWriter{writer: output, remaining: maximumOutput}, result, make([]byte, 1<<20))
	if err != nil || count <= 0 || uint64(count) > maximumOutput {
		return ToolEvidence{}, scanError("SCAN_LIMIT_REACHED", "The Office PDF exceeds the renderer output bound.", "Reduce the document and retry.", err)
	}
	return transformer.tool, nil
}

func runBoundedCommand(ctx context.Context, executable string, arguments []string, input io.Reader, maximum uint64, environment []string) ([]byte, error) {
	if ctx == nil || executable == "" || maximum == 0 || maximum > 1<<20 {
		return nil, errors.New("invalid bounded command")
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	if environment == nil {
		environment = []string{"LANG=C.UTF-8"}
	}
	command.Env = append([]string(nil), environment...)
	command.Stdin = input
	var stdout boundedCommandBuffer
	stdout.remaining = maximum
	command.Stdout = &stdout
	command.Stderr = io.Discard
	err := command.Run()
	if ctx.Err() != nil {
		return nil, contextScanError(ctx.Err())
	}
	if err != nil || stdout.exceeded {
		clear(stdout.buffer.Bytes())
		return nil, fmt.Errorf("bounded command failed")
	}
	return bytes.Clone(stdout.buffer.Bytes()), nil
}

type boundedCommandBuffer struct {
	buffer    bytes.Buffer
	remaining uint64
	exceeded  bool
}

func (writer *boundedCommandBuffer) Write(value []byte) (int, error) {
	if uint64(len(value)) > writer.remaining {
		writer.exceeded = true
		return 0, errors.New("bounded command output exceeded")
	}
	written, err := writer.buffer.Write(value)
	writer.remaining -= uint64(written)
	return written, err
}
