package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultClamdChunkBytes    = 1 << 20
	DefaultClamdResponseBytes = 64 << 10
	DefaultClamdIdleTimeout   = 30 * time.Second
)

type ClamdDialer func(context.Context) (net.Conn, error)

func UnixClamdDialer(socketPath string) (ClamdDialer, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || strings.ContainsRune(socketPath, '\x00') {
		return nil, scanError("CLAMAV_SOCKET_INVALID", "The ClamAV Unix socket path is invalid.", "Use the fixed absolute clamd socket from the verified scanner image.", nil)
	}
	return func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socketPath)
	}, nil
}

type ClamdClient struct {
	Dial             ClamdDialer
	MaxInputBytes    uint64
	ChunkBytes       int
	MaxResponseBytes int
	IdleTimeout      time.Duration
}

type ClamResult struct {
	Finding Finding
	Clean   bool
}

func (client ClamdClient) Scan(ctx context.Context, input io.Reader, expectedSize uint64) (ClamResult, error) {
	if client.Dial == nil || input == nil {
		return ClamResult{}, scanError("CLAMAV_UNAVAILABLE", "The ClamAV scanner is unavailable.", "Recreate the scanner from the verified image and retry.", nil)
	}
	maximum := client.MaxInputBytes
	if maximum == 0 || maximum > 1<<40 || expectedSize > maximum {
		return ClamResult{}, scanError("SCAN_LIMIT_REACHED", "A file exceeds the configured ClamAV input limit.", "Reduce the selected content and restart the workflow.", nil)
	}
	chunkBytes := client.ChunkBytes
	if chunkBytes == 0 {
		chunkBytes = DefaultClamdChunkBytes
	}
	if chunkBytes < 4096 || chunkBytes > DefaultClamdChunkBytes {
		return ClamResult{}, scanError("SCAN_LIMIT_INVALID", "The ClamAV stream chunk bound is invalid.", "Use chunks from 4 KiB through 1 MiB.", nil)
	}
	responseBytes := client.MaxResponseBytes
	if responseBytes == 0 {
		responseBytes = DefaultClamdResponseBytes
	}
	if responseBytes < 1024 || responseBytes > 1<<20 {
		return ClamResult{}, scanError("SCAN_LIMIT_INVALID", "The ClamAV response bound is invalid.", "Use a response limit from 1 KiB through 1 MiB.", nil)
	}
	idle := client.IdleTimeout
	if idle == 0 {
		idle = DefaultClamdIdleTimeout
	}
	if idle < time.Millisecond || idle > 5*time.Minute {
		return ClamResult{}, scanError("SCAN_LIMIT_INVALID", "The ClamAV idle timeout is invalid.", "Use an idle timeout from one millisecond through five minutes.", nil)
	}
	if err := ctx.Err(); err != nil {
		return ClamResult{}, contextScanError(err)
	}
	connection, err := client.Dial(ctx)
	if err != nil {
		return ClamResult{}, scanError("CLAMAV_UNAVAILABLE", "The ClamAV Unix service could not be reached.", "Verify clamd is healthy inside the scanner and retry.", err)
	}
	defer connection.Close()
	deadline := func() error { return setOperationDeadline(ctx, connection, idle) }
	if err := deadline(); err != nil {
		return ClamResult{}, err
	}
	if _, err := io.WriteString(connection, "zINSTREAM\x00"); err != nil {
		return ClamResult{}, clamdTransportError(ctx, err)
	}
	buffer := make([]byte, chunkBytes)
	var transferred uint64
	for transferred < expectedSize {
		if err := ctx.Err(); err != nil {
			return ClamResult{}, contextScanError(err)
		}
		remaining := expectedSize - transferred
		readBuffer := buffer
		if remaining < uint64(len(readBuffer)) {
			readBuffer = readBuffer[:remaining]
		}
		count, readErr := io.ReadFull(input, readBuffer)
		if count > 0 {
			if err := deadline(); err != nil {
				return ClamResult{}, err
			}
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], uint32(count))
			if err := writeFull(connection, header[:]); err != nil {
				return ClamResult{}, clamdTransportError(ctx, err)
			}
			if err := writeFull(connection, readBuffer[:count]); err != nil {
				return ClamResult{}, clamdTransportError(ctx, err)
			}
			transferred += uint64(count)
		}
		if readErr != nil {
			return ClamResult{}, scanError("SCAN_FILE_SKIPPED", "A file ended before its declared size was scanned.", "Reject the quarantine and repeat the download in a fresh session.", readErr)
		}
	}
	var extra [1]byte
	if count, err := input.Read(extra[:]); count != 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return ClamResult{}, scanError("SCAN_FILE_CHANGED", "A file did not match its inventoried size during scanning.", "Reject the quarantine and repeat the download in a fresh session.", err)
	}
	if err := deadline(); err != nil {
		return ClamResult{}, err
	}
	if err := writeFull(connection, []byte{0, 0, 0, 0}); err != nil {
		return ClamResult{}, clamdTransportError(ctx, err)
	}
	if err := deadline(); err != nil {
		return ClamResult{}, err
	}
	response, err := readNULTerminated(connection, responseBytes)
	if err != nil {
		return ClamResult{}, clamdTransportError(ctx, err)
	}
	return ParseClamdResponse(response)
}

func ParseClamdResponse(response []byte) (ClamResult, error) {
	if len(response) == 0 || len(response) > DefaultClamdResponseBytes || strings.ContainsAny(string(response), "\x00\r\n") {
		return ClamResult{}, scanError("SCAN_ERROR", "ClamAV returned an invalid bounded response.", "Destroy the scanner and retry with the verified ClamAV build.", nil)
	}
	text := string(response)
	const prefix = "stream: "
	if !strings.HasPrefix(text, prefix) {
		return ClamResult{}, scanError("SCAN_ERROR", "ClamAV returned an unrecognized response.", "Destroy the scanner and retry with the verified ClamAV build.", nil)
	}
	verdict := strings.TrimPrefix(text, prefix)
	if verdict == "OK" {
		return ClamResult{Clean: true, Finding: Finding{Code: "CLAMAV_CLEAN", Severity: SeverityInfo, Detail: "ClamAV completed without a signature finding."}}, nil
	}
	if identifier, found := strings.CutSuffix(verdict, " FOUND"); found && validIdentity(identifier) {
		return ClamResult{Finding: Finding{Code: "MALWARE_DETECTED", Severity: SeverityBlocking, Detail: "ClamAV reported a malware or heuristic detection.", Identifier: identifier}}, nil
	}
	if detail, found := strings.CutSuffix(verdict, " ERROR"); found {
		lower := strings.ToLower(detail)
		switch {
		case strings.Contains(lower, "encrypted"):
			return ClamResult{Finding: Finding{Code: "ARCHIVE_ENCRYPTED", Severity: SeverityBlocking, Detail: "ClamAV reported encrypted or uninspectable content."}}, nil
		case strings.Contains(lower, "size limit"), strings.Contains(lower, "scan size"), strings.Contains(lower, "limits exceeded"):
			return ClamResult{Finding: Finding{Code: "SCAN_LIMIT_REACHED", Severity: SeverityBlocking, Detail: "ClamAV reported that a configured scan limit was reached."}}, nil
		case strings.Contains(lower, "timeout"):
			return ClamResult{Finding: Finding{Code: "SCAN_TIMEOUT", Severity: SeverityBlocking, Detail: "ClamAV reported an internal scan timeout."}}, nil
		case strings.Contains(lower, "access denied"), strings.Contains(lower, "can't read"), strings.Contains(lower, "cannot read"):
			return ClamResult{Finding: Finding{Code: "SCAN_FILE_SKIPPED", Severity: SeverityBlocking, Detail: "ClamAV could not inspect the complete file."}}, nil
		default:
			return ClamResult{Finding: Finding{Code: "SCAN_ERROR", Severity: SeverityBlocking, Detail: "ClamAV reported a scan error."}}, nil
		}
	}
	return ClamResult{}, scanError("SCAN_ERROR", "ClamAV returned an unrecognized verdict.", "Destroy the scanner and retry with the verified ClamAV build.", nil)
}

type InventoryOpener func(context.Context, InventoryEntry) (io.ReadCloser, error)

type ScanSummary struct {
	Findings     []Finding
	ScannedFiles uint64
	Complete     bool
}

func ScanInventory(ctx context.Context, inventory Inventory, opener InventoryOpener, scanner interface {
	Scan(context.Context, io.Reader, uint64) (ClamResult, error)
}) (ScanSummary, error) {
	if opener == nil || scanner == nil || len(inventory.Entries) == 0 {
		return ScanSummary{}, scanError("SCAN_INVENTORY_INVALID", "The inventory or scanner input boundary is incomplete.", "Repeat offline inventory before scanning every requested file.", nil)
	}
	summary := ScanSummary{Findings: make([]Finding, 0, len(inventory.Entries))}
	for _, entry := range inventory.Entries {
		if err := ctx.Err(); err != nil {
			return summary, contextScanError(err)
		}
		reader, err := opener(ctx, entry)
		if err != nil {
			return summary, scanError("SCAN_FILE_SKIPPED", "An inventoried file could not be reopened safely.", "Reject the quarantine and repeat the download in a fresh session.", err)
		}
		result, scanErr := scanner.Scan(ctx, reader, entry.SizeBytes)
		closeErr := reader.Close()
		if scanErr != nil {
			return summary, scanErr
		}
		if closeErr != nil {
			return summary, scanError("SCAN_FILE_SKIPPED", "An inventoried file could not be closed safely after scanning.", "Destroy the scanner and retry in a fresh session.", closeErr)
		}
		result.Finding.RelativePath = entry.RelativePath
		if !result.Finding.valid() {
			return summary, scanError("SCAN_ERROR", "A ClamAV finding was incomplete.", "Destroy the scanner and retry with the verified scanner image.", nil)
		}
		summary.Findings = append(summary.Findings, result.Finding)
		summary.ScannedFiles++
	}
	summary.Complete = summary.ScannedFiles == uint64(len(inventory.Entries))
	return summary, nil
}

func setOperationDeadline(ctx context.Context, connection net.Conn, idle time.Duration) error {
	deadline := time.Now().Add(idle)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return scanError("SCAN_ERROR", "The ClamAV transport deadline could not be enforced.", "Destroy the scanner and retry with the verified scanner image.", err)
	}
	return nil
}

func clamdTransportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return contextScanError(ctx.Err())
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return scanError("SCAN_TIMEOUT", "The ClamAV stream exceeded its idle deadline.", "Destroy the scanner and retry within the bounded scan policy.", err)
	}
	return scanError("SCAN_ERROR", "The bounded ClamAV stream failed.", "Destroy the scanner and retry with the verified scanner image.", err)
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count <= 0 || count > len(data) {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}

func readNULTerminated(reader io.Reader, maximum int) ([]byte, error) {
	result := make([]byte, 0, min(maximum, 4096))
	buffer := make([]byte, 4096)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			for index, value := range buffer[:count] {
				if value == 0 {
					if index != count-1 {
						return nil, errors.New("trailing ClamAV response bytes")
					}
					if len(result)+index > maximum {
						return nil, errors.New("ClamAV response limit exceeded")
					}
					return append(result, buffer[:index]...), nil
				}
			}
			if len(result)+count > maximum {
				return nil, errors.New("ClamAV response limit exceeded")
			}
			result = append(result, buffer[:count]...)
		}
		if err != nil {
			return nil, err
		}
	}
}
