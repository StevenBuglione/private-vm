package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/StevenBuglione/private-vm/internal/policy"
)

type ContentClass string

const (
	ContentPDF         ContentClass = "pdf"
	ContentOffice      ContentClass = "office"
	ContentImage       ContentClass = "image"
	ContentMedia       ContentClass = "media"
	ContentText        ContentClass = "text"
	ContentArchive     ContentClass = "archive"
	ContentActive      ContentClass = "active"
	ContentUnsupported ContentClass = "unsupported"
)

type DocumentEvidence struct {
	Pages          uint32
	MaximumWidth   uint32
	MaximumHeight  uint32
	MacrosObserved bool
	Complete       bool
}

type MediaEvidence struct {
	DurationSeconds uint64
	MaximumWidth    uint32
	MaximumHeight   uint32
	Streams         uint32
	Attachments     uint32
	Chapters        uint32
	Complete        bool
}

type DocumentProbe interface {
	ProbeDocument(context.Context, io.ReadSeeker) (DocumentEvidence, ToolEvidence, error)
}

type MediaProbe interface {
	ProbeMedia(context.Context, io.ReadSeeker) (MediaEvidence, ToolEvidence, error)
}

type ReconstructionLimits struct {
	MaxOutputBytes   uint64
	MaxImagePixels   uint64
	MaxDocumentPages uint32
	MaxDimension     uint32
	MaxMediaDuration uint64
	MaxMediaStreams  uint32
	MaxTextBytes     uint64
}

type Reconstructor struct {
	Policy     policy.Policy
	Sandbox    ExtractionSandbox
	Classifier MIMEClassifier
	Rescanner  interface {
		Scan(context.Context, io.Reader, uint64) (ClamResult, error)
	}
	PDF            Transformer
	OfficeRenderer Transformer
	Media          Transformer
	DocumentProbe  DocumentProbe
	MediaProbe     MediaProbe
	Limits         ReconstructionLimits
}

type ReconstructedOutput struct {
	mu             sync.Mutex
	parent         *os.Root
	name           string
	path           string
	identity       fileInfoIdentity
	cleaned        bool
	SizeBytes      uint64
	SHA256         string
	DetectedMIME   string
	Transformation string
	Tools          []ToolEvidence
}

func (output *ReconstructedOutput) Open() (*os.File, error) {
	if output == nil {
		return nil, scanError("SANITIZED_OUTPUT_UNAVAILABLE", "The sanitized output is unavailable.", "Repeat reconstruction in a fresh scanner.", nil)
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.cleaned {
		return nil, scanError("SANITIZED_OUTPUT_UNAVAILABLE", "The sanitized output was already destroyed.", "Repeat reconstruction in a fresh scanner.", nil)
	}
	file, err := output.parent.Open(output.name)
	if err != nil {
		return nil, scanError("SANITIZED_OUTPUT_CHANGED", "The sanitized output could not be reopened safely.", "Reject the output and repeat reconstruction.", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !sameFileInfoIdentity(info, output.identity) || info.Size() < 0 || uint64(info.Size()) != output.SizeBytes {
		file.Close()
		return nil, scanError("SANITIZED_OUTPUT_CHANGED", "The sanitized output identity changed.", "Reject the output and repeat reconstruction.", err)
	}
	return file, nil
}

func (output *ReconstructedOutput) Cleanup() error {
	if output == nil {
		return nil
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.cleaned {
		return nil
	}
	info, err := output.parent.Lstat(output.name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			output.cleaned = true
			return output.parent.Close()
		}
		return scanError("SANITIZED_OUTPUT_CLEANUP_INCOMPLETE", "The sanitized output could not be revalidated for cleanup.", "Destroy the scanner so the cleanup owner can retry.", err)
	}
	if !info.Mode().IsRegular() || !sameFileInfoIdentity(info, output.identity) {
		return scanError("SANITIZED_OUTPUT_CLEANUP_INCOMPLETE", "The sanitized output identity changed before cleanup.", "Destroy the scanner; cleanup will preserve and report the substituted path.", nil)
	}
	if err := output.parent.Remove(output.name); err != nil {
		return scanError("SANITIZED_OUTPUT_CLEANUP_INCOMPLETE", "The sanitized output could not be removed.", "Destroy the scanner so the cleanup owner can retry.", err)
	}
	output.cleaned = true
	return output.parent.Close()
}

func (reconstructor Reconstructor) Reconstruct(ctx context.Context, input *os.File, entry InventoryEntry) (*ReconstructedOutput, error) {
	if input == nil || reconstructor.Policy.Validate() != nil || reconstructor.Policy.Mode() != policy.ModeSafe ||
		reconstructor.Classifier == nil || reconstructor.Rescanner == nil {
		return nil, scanError("SANITIZER_CONFIG_INVALID", "The safe reconstruction boundary is incomplete.", "Use the validated safe policy and verified scanner toolchain.", nil)
	}
	if entry.SizeBytes == 0 || len(entry.SHA256) != 64 || !validMIME(entry.DetectedMIME) {
		return nil, scanError("SCAN_INVENTORY_INVALID", "The reconstruction input lacks complete inventory evidence.", "Repeat offline inventory and malware scanning before reconstruction.", nil)
	}
	if err := verifyReconstructionInput(ctx, input, entry); err != nil {
		return nil, err
	}
	limits, err := validateReconstructionLimits(reconstructor.Limits)
	if err != nil {
		return nil, err
	}
	class := classifyContent(entry.DetectedMIME)
	if class == ContentActive {
		return nil, scanError("ACTIVE_CONTENT_BLOCKED", "Executable, script, package or disk-image content cannot be reconstructed under safe policy.", "Reject the content; raw promotion is not available in the safe workflow.", nil)
	}
	if class == ContentArchive {
		return nil, scanError("ARCHIVE_RECURSION_REQUIRED", "Archive members must be extracted, inventoried and scanned individually.", "Run bounded recursive archive processing before reconstruction.", nil)
	}
	if class == ContentUnsupported {
		return nil, scanError("SANITIZER_UNSUPPORTED_TYPE", "The content type has no safe reconstruction backend.", "Reject unsupported content under the safe policy.", nil)
	}
	output, destination, err := newReconstructedOutput(reconstructor.Sandbox)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*ReconstructedOutput, error) {
		_ = destination.Close()
		if cleanupErr := output.Cleanup(); cleanupErr != nil {
			return nil, cleanupErr
		}
		return nil, cause
	}
	var tools []ToolEvidence
	var expectedMIME, transformation string
	var expectedDocumentPages uint32
	var sourceMedia MediaEvidence
	bounded := &boundedTransformWriter{writer: destination, remaining: limits.MaxOutputBytes}
	switch class {
	case ContentPDF:
		if reconstructor.PDF == nil || reconstructor.DocumentProbe == nil {
			return fail(missingBackendError())
		}
		probe, tool, err := reconstructor.DocumentProbe.ProbeDocument(ctx, input)
		if err != nil || !validDocumentEvidence(probe, limits) || !tool.valid() {
			return fail(scanError("SANITIZER_FAILED", "PDF structure could not be bounded before raster reconstruction.", "Reject the document and destroy the disposable scanner.", err))
		}
		tools = append(tools, tool)
		expectedDocumentPages = probe.Pages
		transformTool, err := reconstructor.PDF.Transform(ctx, input, bounded, limits.MaxOutputBytes)
		if err != nil {
			return fail(transformFailure(err, bounded))
		}
		tools = append(tools, transformTool)
		expectedMIME, transformation = "application/pdf", "pdf-raster-rebuild-v1"
	case ContentOffice:
		if reconstructor.OfficeRenderer == nil || reconstructor.PDF == nil || reconstructor.DocumentProbe == nil {
			return fail(missingBackendError())
		}
		intermediate, intermediateFile, err := newReconstructedOutput(reconstructor.Sandbox)
		if err != nil {
			return fail(err)
		}
		intermediateBounded := &boundedTransformWriter{writer: intermediateFile, remaining: limits.MaxOutputBytes}
		renderTool, renderErr := reconstructor.OfficeRenderer.Transform(ctx, input, intermediateBounded, limits.MaxOutputBytes)
		closeErr := intermediateFile.Close()
		if renderErr != nil || closeErr != nil || intermediateBounded.exceeded {
			_ = intermediate.Cleanup()
			if intermediateBounded.exceeded {
				return fail(scanError("SCAN_LIMIT_REACHED", "Office intermediate output exceeds the configured byte limit.", "Reject the document or reduce its bounded rendered output.", errTransformOutputLimit))
			}
			return fail(scanError("SANITIZER_FAILED", "Office rendering did not produce a complete intermediate PDF.", "Reject the document and destroy the disposable scanner.", errors.Join(renderErr, closeErr)))
		}
		if err := finalizeOutputIdentity(intermediate); err != nil {
			_ = intermediate.Cleanup()
			return fail(err)
		}
		intermediateReader, err := intermediate.Open()
		if err != nil {
			_ = intermediate.Cleanup()
			return fail(err)
		}
		probe, probeTool, probeErr := reconstructor.DocumentProbe.ProbeDocument(ctx, intermediateReader)
		if _, err := intermediateReader.Seek(0, io.SeekStart); err != nil && probeErr == nil {
			probeErr = err
		}
		if probeErr != nil || !validDocumentEvidence(probe, limits) || !renderTool.valid() || !probeTool.valid() {
			intermediateReader.Close()
			_ = intermediate.Cleanup()
			return fail(scanError("SANITIZER_FAILED", "Rendered Office output could not be bounded as PDF.", "Reject the document and destroy the disposable scanner.", probeErr))
		}
		pdfTool, transformErr := reconstructor.PDF.Transform(ctx, intermediateReader, bounded, limits.MaxOutputBytes)
		closeReaderErr := intermediateReader.Close()
		cleanupErr := intermediate.Cleanup()
		if transformErr != nil || closeReaderErr != nil || cleanupErr != nil {
			if transformErr != nil {
				return fail(transformFailure(transformErr, bounded))
			}
			return fail(scanError("SANITIZER_FAILED", "Office reconstruction cleanup did not complete.", "Reject the document and destroy the disposable scanner.", errors.Join(closeReaderErr, cleanupErr)))
		}
		tools = append(tools, renderTool, probeTool, pdfTool)
		expectedDocumentPages = probe.Pages
		expectedMIME, transformation = "application/pdf", "office-render-pdf-raster-rebuild-v1"
	case ContentImage:
		tool, err := (ImageTransformer{MaxPixels: limits.MaxImagePixels, MaxDimension: limits.MaxDimension}).Transform(ctx, input, bounded, limits.MaxOutputBytes)
		if err != nil {
			return fail(transformFailure(err, bounded))
		}
		tools = append(tools, tool)
		expectedMIME, transformation = "image/png", "image-decode-strip-reencode-png-v1"
	case ContentMedia:
		if reconstructor.Media == nil || reconstructor.MediaProbe == nil {
			return fail(missingBackendError())
		}
		probe, probeTool, err := reconstructor.MediaProbe.ProbeMedia(ctx, input)
		if err != nil || !validMediaEvidence(probe, limits) || !probeTool.valid() {
			return fail(scanError("SANITIZER_FAILED", "Media structure could not be bounded before full re-encode.", "Reject the media and destroy the disposable scanner.", err))
		}
		tool, err := reconstructor.Media.Transform(ctx, input, bounded, limits.MaxOutputBytes)
		if err != nil {
			return fail(transformFailure(err, bounded))
		}
		tools = append(tools, probeTool, tool)
		sourceMedia = probe
		if strings.HasPrefix(entry.DetectedMIME, "audio/") {
			expectedMIME, transformation = "audio/mp4", "media-full-decode-aac-v1"
		} else {
			expectedMIME, transformation = "video/mp4", "media-full-decode-h264-aac-v1"
		}
	case ContentText:
		tool, err := (TextTransformer{MaxBytes: limits.MaxTextBytes}).Transform(ctx, input, bounded, limits.MaxOutputBytes)
		if err != nil {
			return fail(transformFailure(err, bounded))
		}
		tools = append(tools, tool)
		expectedMIME, transformation = "text/plain", "text-utf8-line-normalize-v1"
	}
	if bounded.exceeded {
		return fail(scanError("SCAN_LIMIT_REACHED", "Sanitized output exceeds the configured byte limit.", "Reject this input or reduce its bounded reconstruction output.", errTransformOutputLimit))
	}
	if err := destination.Sync(); err != nil {
		return fail(scanError("SANITIZER_FAILED", "Sanitized output could not be finalized.", "Reject the output and destroy the disposable scanner.", err))
	}
	if err := destination.Close(); err != nil {
		return fail(scanError("SANITIZER_FAILED", "Sanitized output could not be closed safely.", "Reject the output and destroy the disposable scanner.", err))
	}
	if err := finalizeOutputIdentity(output); err != nil {
		return fail(err)
	}
	reader, err := output.Open()
	if err != nil {
		return fail(err)
	}
	if class == ContentPDF || class == ContentOffice {
		verification, tool, verifyErr := reconstructor.DocumentProbe.ProbeDocument(ctx, reader)
		if verifyErr != nil || !validDocumentEvidence(verification, limits) || verification.Pages != expectedDocumentPages || verification.MacrosObserved || !tool.valid() {
			reader.Close()
			return fail(scanError("SANITIZED_OUTPUT_INVALID", "Rebuilt PDF page structure could not be verified.", "Reject the output and repeat reconstruction with the verified toolchain.", verifyErr))
		}
		tools = append(tools, tool)
		if _, err := reader.Seek(0, io.SeekStart); err != nil {
			reader.Close()
			return fail(scanError("SANITIZED_OUTPUT_INVALID", "Rebuilt PDF could not be rewound after verification.", "Reject the output and repeat reconstruction.", err))
		}
	}
	if class == ContentMedia {
		verification, tool, verifyErr := reconstructor.MediaProbe.ProbeMedia(ctx, reader)
		durationDifference := sourceMedia.DurationSeconds > verification.DurationSeconds
		if !durationDifference {
			durationDifference = verification.DurationSeconds-sourceMedia.DurationSeconds > 2
		} else {
			durationDifference = sourceMedia.DurationSeconds-verification.DurationSeconds > 2
		}
		if verifyErr != nil || !validMediaEvidence(verification, limits) || verification.Attachments != 0 || verification.Chapters != 0 || durationDifference || !tool.valid() {
			reader.Close()
			return fail(scanError("SANITIZED_OUTPUT_INVALID", "Re-encoded media structure could not be verified.", "Reject the output and repeat reconstruction with the verified toolchain.", verifyErr))
		}
		tools = append(tools, tool)
		if _, err := reader.Seek(0, io.SeekStart); err != nil {
			reader.Close()
			return fail(scanError("SANITIZED_OUTPUT_INVALID", "Re-encoded media could not be rewound after verification.", "Reject the output and repeat reconstruction.", err))
		}
	}
	detected, digest, err := identifyAndHashOutput(ctx, reader, output.SizeBytes, reconstructor.Classifier)
	if err != nil {
		reader.Close()
		return fail(err)
	}
	identityMustChange := class == ContentPDF || class == ContentOffice || class == ContentMedia
	if detected != expectedMIME || (identityMustChange && digest == entry.SHA256) {
		reader.Close()
		return fail(scanError("SANITIZED_OUTPUT_INVALID", "Reconstructed output did not match its required new safe type and identity.", "Reject the output and repeat reconstruction with the verified toolchain.", nil))
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		reader.Close()
		return fail(scanError("SANITIZED_OUTPUT_INVALID", "Reconstructed output could not be rewound for rescanning.", "Reject the output and repeat reconstruction.", err))
	}
	result, scanErr := reconstructor.Rescanner.Scan(ctx, reader, output.SizeBytes)
	closeReaderErr := reader.Close()
	if scanErr != nil || closeReaderErr != nil || !result.Clean || result.Finding.Code != "CLAMAV_CLEAN" {
		return fail(scanError("SANITIZED_OUTPUT_REJECTED", "Reconstructed output did not pass its mandatory rescan.", "Reject the output and destroy the disposable scanner.", errors.Join(scanErr, closeReaderErr)))
	}
	for _, tool := range tools {
		if !tool.valid() {
			return fail(scanError("SANITIZER_FAILED", "Reconstruction tool evidence is incomplete.", "Reject the output and reinstall the verified scanner image.", nil))
		}
	}
	output.SHA256 = digest
	output.DetectedMIME = detected
	output.Transformation = transformation
	output.Tools = append([]ToolEvidence(nil), tools...)
	return output, nil
}

type ImageTransformer struct {
	MaxPixels    uint64
	MaxDimension uint32
}

func (transformer ImageTransformer) Transform(ctx context.Context, input io.ReadSeeker, output io.Writer, _ uint64) (ToolEvidence, error) {
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "Image input could not be rewound.", "Reject this image and destroy the disposable scanner.", err)
	}
	configuration, format, err := image.DecodeConfig(&contextReader{ctx: ctx, reader: input})
	if err != nil || (format != "png" && format != "jpeg") || configuration.Width <= 0 || configuration.Height <= 0 ||
		uint64(configuration.Width) > uint64(transformer.MaxDimension) || uint64(configuration.Height) > uint64(transformer.MaxDimension) ||
		uint64(configuration.Width) > transformer.MaxPixels/uint64(configuration.Height) {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "Image dimensions, format or pixel count violate policy.", "Reject the image or use a supported bounded PNG/JPEG input.", err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "Image input could not be rewound for decoding.", "Reject this image and destroy the disposable scanner.", err)
	}
	decoded, _, err := image.Decode(&contextReader{ctx: ctx, reader: input})
	if err != nil {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "Image decoding did not complete.", "Reject this image and destroy the disposable scanner.", err)
	}
	if err := png.Encode(output, decoded); err != nil {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "Image re-encoding did not complete.", "Reject this image and destroy the disposable scanner.", err)
	}
	return ToolEvidence{Name: "go-image-png", Version: "go1.26"}, nil
}

type TextTransformer struct{ MaxBytes uint64 }

func (transformer TextTransformer) Transform(ctx context.Context, input io.ReadSeeker, output io.Writer, _ uint64) (ToolEvidence, error) {
	if transformer.MaxBytes == 0 || transformer.MaxBytes > 64<<20 {
		return ToolEvidence{}, missingBackendError()
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "Text input could not be rewound.", "Reject this input and destroy the disposable scanner.", err)
	}
	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: input}, int64(transformer.MaxBytes)+1))
	if err != nil || uint64(len(data)) > transformer.MaxBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		clear(data)
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "Text input is not bounded NUL-free UTF-8.", "Reject binary, oversized or invalidly encoded text.", err)
	}
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	normalized = bytes.ReplaceAll(normalized, []byte("\r"), []byte("\n"))
	_, err = output.Write(normalized)
	clear(data)
	clear(normalized)
	if err != nil {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "Normalized text output could not be written.", "Reject this input and destroy the disposable scanner.", err)
	}
	return ToolEvidence{Name: "private-vm-text-normalizer", Version: "1"}, nil
}

func classifyContent(mime string) ContentClass {
	switch mime {
	case "application/pdf":
		return ContentPDF
	case "application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"application/vnd.oasis.opendocument.text", "application/vnd.oasis.opendocument.spreadsheet", "application/vnd.oasis.opendocument.presentation":
		return ContentOffice
	case "image/png", "image/jpeg":
		return ContentImage
	case "text/plain":
		return ContentText
	case "application/zip", "application/x-tar", "application/gzip", "application/x-7z-compressed", "application/x-rar-compressed":
		return ContentArchive
	case "application/x-executable", "application/x-pie-executable", "application/x-sharedlib", "application/x-dosexec",
		"application/x-shellscript", "application/javascript", "text/javascript", "application/x-iso9660-image",
		"application/x-qemu-disk", "application/vnd.debian.binary-package", "application/x-rpm":
		return ContentActive
	}
	if strings.HasPrefix(mime, "audio/") || strings.HasPrefix(mime, "video/") {
		return ContentMedia
	}
	return ContentUnsupported
}

func validateReconstructionLimits(limits ReconstructionLimits) (ReconstructionLimits, error) {
	if limits.MaxOutputBytes == 0 || limits.MaxOutputBytes > 4<<40 || limits.MaxImagePixels == 0 || limits.MaxImagePixels > 1_000_000_000 ||
		limits.MaxDocumentPages == 0 || limits.MaxDocumentPages > 10000 || limits.MaxDimension == 0 || limits.MaxDimension > 100000 ||
		limits.MaxMediaDuration == 0 || limits.MaxMediaDuration > 7*24*60*60 || limits.MaxMediaStreams == 0 || limits.MaxMediaStreams > 128 ||
		limits.MaxTextBytes == 0 || limits.MaxTextBytes > 64<<20 {
		return ReconstructionLimits{}, scanError("SCAN_LIMIT_INVALID", "Reconstruction limits are outside supported bounds.", "Use finite image, document, media, text and output limits.", nil)
	}
	return limits, nil
}

func validDocumentEvidence(evidence DocumentEvidence, limits ReconstructionLimits) bool {
	return evidence.Complete && evidence.Pages > 0 && evidence.Pages <= limits.MaxDocumentPages &&
		evidence.MaximumWidth > 0 && evidence.MaximumWidth <= limits.MaxDimension &&
		evidence.MaximumHeight > 0 && evidence.MaximumHeight <= limits.MaxDimension
}

func validMediaEvidence(evidence MediaEvidence, limits ReconstructionLimits) bool {
	return evidence.Complete && evidence.DurationSeconds > 0 && evidence.DurationSeconds <= limits.MaxMediaDuration &&
		evidence.Streams > 0 && evidence.Streams <= limits.MaxMediaStreams && evidence.Attachments <= limits.MaxMediaStreams &&
		evidence.MaximumWidth <= limits.MaxDimension && evidence.MaximumHeight <= limits.MaxDimension
}

func verifyReconstructionInput(ctx context.Context, input *os.File, entry InventoryEntry) error {
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != entry.SizeBytes {
		return scanError("SCAN_ENTRY_CHANGED", "The reconstruction input no longer matches its inventory size.", "Reject the quarantine and repeat the download in a fresh session.", err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return scanError("SCAN_ENTRY_CHANGED", "The reconstruction input could not be rewound for verification.", "Reject the quarantine and repeat the download in a fresh session.", err)
	}
	hasher := sha256.New()
	written, err := io.CopyBuffer(hasher, &contextReader{ctx: ctx, reader: io.LimitReader(input, int64(entry.SizeBytes)+1)}, make([]byte, 1<<20))
	if ctx.Err() != nil {
		return contextScanError(ctx.Err())
	}
	if err != nil || written < 0 || uint64(written) != entry.SizeBytes || hex.EncodeToString(hasher.Sum(nil)) != entry.SHA256 {
		return scanError("SCAN_ENTRY_CHANGED", "The reconstruction input no longer matches its inventoried hash.", "Reject the quarantine and repeat the download in a fresh session.", err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return scanError("SCAN_ENTRY_CHANGED", "The reconstruction input could not be rewound after verification.", "Reject the quarantine and repeat the download in a fresh session.", err)
	}
	return nil
}

func newReconstructedOutput(sandbox ExtractionSandbox) (*ReconstructedOutput, *os.File, error) {
	if !filepath.IsAbs(sandbox.ParentPath) || filepath.Clean(sandbox.ParentPath) != sandbox.ParentPath ||
		!sandbox.Tmpfs || !sandbox.PrivateMountNamespace || sandbox.WorkerUID <= 0 || os.Geteuid() != sandbox.WorkerUID ||
		os.Getegid() != sandbox.WorkerGID || !extractionParentIsTmpfs(sandbox.ParentPath) {
		return nil, nil, scanError("SANITIZER_SANDBOX_UNVERIFIED", "The reconstruction sandbox is not a verified unprivileged private tmpfs.", "Run reconstruction as the scanner worker in its bounded private tmpfs.", nil)
	}
	parent, err := os.OpenRoot(sandbox.ParentPath)
	if err != nil {
		return nil, nil, scanError("SANITIZER_SANDBOX_UNVERIFIED", "The reconstruction parent could not be opened safely.", "Recreate the scanner worker sandbox and retry.", err)
	}
	file, err := os.CreateTemp(sandbox.ParentPath, "private-vm-output-")
	if err != nil {
		parent.Close()
		return nil, nil, scanError("SANITIZER_FAILED", "A volatile sanitized output could not be created.", "Destroy the scanner and retry in a fresh session.", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		_ = os.Remove(file.Name())
		parent.Close()
		return nil, nil, scanError("SANITIZER_FAILED", "Sanitized output permissions could not be enforced.", "Destroy the scanner and retry in a fresh session.", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		_ = os.Remove(file.Name())
		parent.Close()
		return nil, nil, scanError("SANITIZER_FAILED", "Sanitized output identity could not be captured.", "Destroy the scanner and retry in a fresh session.", err)
	}
	return &ReconstructedOutput{parent: parent, name: filepath.Base(file.Name()), path: file.Name(), identity: captureFileInfoIdentity(info)}, file, nil
}

func finalizeOutputIdentity(output *ReconstructedOutput) error {
	info, err := output.parent.Lstat(output.name)
	if err != nil || !info.Mode().IsRegular() || !sameFileInfoIdentity(info, output.identity) || info.Size() <= 0 {
		return scanError("SANITIZED_OUTPUT_INVALID", "Sanitized output is empty or changed identity.", "Reject the output and repeat reconstruction.", err)
	}
	output.SizeBytes = uint64(info.Size())
	return nil
}

func identifyAndHashOutput(ctx context.Context, reader *os.File, size uint64, classifier MIMEClassifier) (string, string, error) {
	prefixSize := uint64(DefaultInventoryPrefixBytes)
	if size < prefixSize {
		prefixSize = size
	}
	prefix := make([]byte, prefixSize)
	if _, err := io.ReadFull(reader, prefix); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		clear(prefix)
		return "", "", scanError("SANITIZED_OUTPUT_INVALID", "Sanitized output could not be identified completely.", "Reject the output and repeat reconstruction.", err)
	}
	mime, err := classifier.Classify(ctx, prefix)
	clear(prefix)
	if err != nil || !validMIME(mime) {
		return "", "", scanError("SANITIZED_OUTPUT_INVALID", "Sanitized output type could not be verified.", "Reject the output and repeat reconstruction.", err)
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return "", "", scanError("SANITIZED_OUTPUT_INVALID", "Sanitized output could not be rewound for hashing.", "Reject the output and repeat reconstruction.", err)
	}
	hasher := sha256.New()
	written, err := io.CopyBuffer(hasher, &contextReader{ctx: ctx, reader: io.LimitReader(reader, int64(size)+1)}, make([]byte, 1<<20))
	if err != nil || written < 0 || uint64(written) != size {
		return "", "", scanError("SANITIZED_OUTPUT_INVALID", "Sanitized output could not be hashed completely.", "Reject the output and repeat reconstruction.", err)
	}
	return mime, hex.EncodeToString(hasher.Sum(nil)), nil
}

func missingBackendError() error {
	return scanError("SANITIZER_UNAVAILABLE", "A required reconstruction backend is unavailable.", "Install the verified scanner image and reject this content until the backend is available.", nil)
}

func transformFailure(err error, bounded *boundedTransformWriter) error {
	if bounded != nil && bounded.exceeded {
		return scanError("SCAN_LIMIT_REACHED", "Sanitized output exceeds the configured byte limit.", "Reject this input or reduce its bounded reconstruction output.", errTransformOutputLimit)
	}
	var stable *Error
	if errors.As(err, &stable) {
		return err
	}
	return scanError("SANITIZER_FAILED", "A reconstruction backend did not complete successfully.", "Reject this input and destroy the disposable scanner.", err)
}
