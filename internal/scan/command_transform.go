package scan

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var errTransformOutputLimit = errors.New("transform output limit exceeded")

type ToolEvidence struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (evidence ToolEvidence) valid() bool {
	return validIdentity(evidence.Name) && validIdentity(evidence.Version)
}

type Transformer interface {
	Transform(context.Context, io.ReadSeeker, io.Writer, uint64) (ToolEvidence, error)
}

// CommandTransformer runs one verified scanner tool with input on stdin and
// output on stdout. Its immutable arguments are constructor-owned and may not
// contain absolute paths, so user filenames never enter argv or environment.
type CommandTransformer struct {
	executable string
	arguments  []string
	tool       ToolEvidence
}

func NewCommandTransformer(executable string, arguments []string, tool ToolEvidence) (CommandTransformer, error) {
	resolved, err := trustedExecutable(executable)
	if err != nil {
		return CommandTransformer{}, err
	}
	if !tool.valid() || len(arguments) > 64 {
		return CommandTransformer{}, scanError("SANITIZER_CONFIG_INVALID", "A sanitizer tool identity or argument set is invalid.", "Install the verified scanner toolchain and retry.", nil)
	}
	copyArguments := append([]string(nil), arguments...)
	for _, argument := range copyArguments {
		if argument == "" || len(argument) > 256 || strings.ContainsAny(argument, "\x00\r\n") || filepath.IsAbs(argument) || strings.Contains(argument, "/proc/") {
			return CommandTransformer{}, scanError("SANITIZER_CONFIG_INVALID", "A sanitizer argument violates the fixed stdin/stdout contract.", "Use only reviewed filename-free arguments from the verified scanner image.", nil)
		}
	}
	return CommandTransformer{executable: resolved, arguments: copyArguments, tool: tool}, nil
}

func (transformer CommandTransformer) Transform(ctx context.Context, input io.ReadSeeker, output io.Writer, maximumOutput uint64) (ToolEvidence, error) {
	if transformer.executable == "" || input == nil || output == nil || maximumOutput == 0 || maximumOutput > 4<<40 {
		return ToolEvidence{}, scanError("SANITIZER_CONFIG_INVALID", "The sanitizer process boundary is incomplete.", "Recreate the scanner from the verified image and retry.", nil)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "The sanitizer input could not be rewound safely.", "Reject this input and destroy the disposable scanner.", err)
	}
	bounded := &boundedTransformWriter{writer: output, remaining: maximumOutput}
	command := exec.CommandContext(ctx, transformer.executable, transformer.arguments...)
	command.Env = []string{"LANG=C.UTF-8"}
	command.Stdin = input
	command.Stdout = bounded
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ToolEvidence{}, contextScanError(ctx.Err())
		}
		if bounded.exceeded {
			return ToolEvidence{}, scanError("SCAN_LIMIT_REACHED", "Sanitized output exceeds the configured byte limit.", "Reject this input or reduce its bounded reconstruction output.", errTransformOutputLimit)
		}
		return ToolEvidence{}, scanError("SANITIZER_FAILED", "A reconstruction tool did not complete successfully.", "Reject this input and destroy the disposable scanner.", err)
	}
	if bounded.exceeded {
		return ToolEvidence{}, scanError("SCAN_LIMIT_REACHED", "Sanitized output exceeds the configured byte limit.", "Reject this input or reduce its bounded reconstruction output.", errTransformOutputLimit)
	}
	return transformer.tool, nil
}

func PDFRasterTransformer(executable, version string) (CommandTransformer, error) {
	return NewCommandTransformer(executable, []string{
		"-q", "-dSAFER", "-dBATCH", "-dNOPAUSE", "-dAutoRotatePages=/None",
		"-sDEVICE=pdfimage24", "-r150", "-sOutputFile=-", "-",
	}, ToolEvidence{Name: "ghostscript-pdfimage24", Version: version})
}

func MediaReencodeTransformer(executable, version string) (CommandTransformer, error) {
	return NewCommandTransformer(executable, []string{
		"-hide_banner", "-loglevel", "error", "-nostdin", "-i", "pipe:0",
		"-map_metadata", "-1", "-map_chapters", "-1", "-map", "0:v:0?", "-map", "0:a:0?",
		"-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac",
		"-movflags", "frag_keyframe+empty_moov", "-f", "mp4", "pipe:1",
	}, ToolEvidence{Name: "ffmpeg-h264-aac", Version: version})
}

type boundedTransformWriter struct {
	writer    io.Writer
	remaining uint64
	exceeded  bool
}

func (writer *boundedTransformWriter) Write(data []byte) (int, error) {
	if uint64(len(data)) > writer.remaining {
		writer.exceeded = true
		return 0, errTransformOutputLimit
	}
	written, err := writer.writer.Write(data)
	if written > 0 {
		writer.remaining -= uint64(written)
	}
	return written, err
}

func trustedExecutable(executable string) (string, error) {
	if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable || strings.ContainsRune(executable, '\x00') {
		return "", scanError("SANITIZER_CONFIG_INVALID", "A sanitizer executable path is invalid.", "Use an absolute executable from the verified scanner image.", nil)
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", scanError("SANITIZER_CONFIG_INVALID", "A sanitizer executable could not be resolved safely.", "Reinstall the verified scanner image and retry.", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || !trustedExecutablePlatform(resolved, info) {
		return "", scanError("SANITIZER_CONFIG_INVALID", "A sanitizer executable is not a trusted non-writable regular file.", "Reinstall the verified scanner image and retry.", err)
	}
	return resolved, nil
}
