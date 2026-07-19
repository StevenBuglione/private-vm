//go:build linux

package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// BuildInventory walks an already verified read-only quarantine mount using
// descriptor-relative operations. It rejects every link and non-regular leaf;
// an entry replacement between observation and open also fails closed.
func BuildInventory(ctx context.Context, rootPath string, limits InventoryLimits, classifier MIMEClassifier) (Inventory, error) {
	limits, err := validateInventoryLimits(limits)
	if err != nil {
		return Inventory{}, err
	}
	if classifier == nil {
		return Inventory{}, scanError("SCAN_CLASSIFIER_UNAVAILABLE", "The content classifier is unavailable.", "Install the verified scanner image with its pinned MIME classifier.", nil)
	}
	if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath || strings.ContainsRune(rootPath, '\x00') {
		return Inventory{}, scanError("QUARANTINE_PATH_INVALID", "The quarantine root path is invalid.", "Use the scanner image's fixed absolute quarantine mount path.", nil)
	}
	rootFD, err := unix.Open(rootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Inventory{}, scanError("QUARANTINE_OPEN_FAILED", "The quarantine root could not be opened safely.", "Verify the read-only quarantine mount and recreate the scanner.", err)
	}
	defer unix.Close(rootFD)

	var inventory Inventory
	seen := make(map[fileIdentity]struct{})
	if err := walkInventory(ctx, rootFD, "", limits, classifier, seen, &inventory); err != nil {
		return Inventory{}, err
	}
	sortInventory(&inventory)
	return inventory, nil
}

type fileIdentity struct {
	device uint64
	inode  uint64
}

func walkInventory(ctx context.Context, directoryFD int, parent string, limits InventoryLimits, classifier MIMEClassifier, seen map[fileIdentity]struct{}, inventory *Inventory) error {
	if err := ctx.Err(); err != nil {
		return contextScanError(err)
	}
	names, err := readDirectoryNames(directoryFD)
	if err != nil {
		return scanError("SCAN_TRAVERSAL_FAILED", "A quarantine directory could not be enumerated safely.", "Reject this quarantine and repeat the download in a fresh session.", err)
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return contextScanError(err)
		}
		if !validPathComponent(name) {
			return scanError("SCAN_PATH_UNSAFE", "A quarantine entry has an unsafe path component.", "Reject this quarantine; unsafe paths are never scanned or promoted.", nil)
		}
		relative := name
		if parent != "" {
			relative = parent + "/" + name
		}
		if len(relative) > limits.MaxPathBytes {
			return scanError("SCAN_LIMIT_REACHED", "A quarantine path exceeds the configured limit.", "Reject the quarantine or use authorized content with shorter paths.", nil)
		}
		var before unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return scanError("SCAN_TRAVERSAL_FAILED", "A quarantine entry changed during inventory.", "Reject this quarantine and repeat the download in a fresh session.", err)
		}
		switch before.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			childFD, err := openRelative(directoryFD, name, uint64(unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC))
			if err != nil {
				return unsafeOpenError(err)
			}
			var after unix.Stat_t
			statErr := unix.Fstat(childFD, &after)
			if statErr != nil || !sameStat(before, after) {
				unix.Close(childFD)
				return scanError("SCAN_ENTRY_CHANGED", "A quarantine directory changed during inventory.", "Reject this quarantine and repeat the download in a fresh session.", statErr)
			}
			err = walkInventory(ctx, childFD, relative, limits, classifier, seen, inventory)
			closeErr := unix.Close(childFD)
			if err != nil {
				return err
			}
			if closeErr != nil {
				return scanError("SCAN_TRAVERSAL_FAILED", "A quarantine directory could not be closed safely.", "Destroy the scanner and retry in a fresh session.", closeErr)
			}
		case unix.S_IFREG:
			if before.Nlink != 1 {
				return scanError("SCAN_HARDLINK_REJECTED", "A quarantine file has multiple hard links.", "Reject this quarantine; hard-linked content is never promoted.", nil)
			}
			identity := fileIdentity{device: uint64(before.Dev), inode: before.Ino}
			if _, exists := seen[identity]; exists {
				return scanError("SCAN_HARDLINK_REJECTED", "A quarantine file identity appears more than once.", "Reject this quarantine; hard-linked content is never promoted.", nil)
			}
			seen[identity] = struct{}{}
			if err := addRegularFile(ctx, directoryFD, name, relative, before, limits, classifier, inventory); err != nil {
				return err
			}
		case unix.S_IFLNK:
			return scanError("SCAN_SYMLINK_REJECTED", "A symbolic link is present in quarantine.", "Reject this quarantine; symbolic links are never followed or promoted.", nil)
		default:
			return scanError("SCAN_SPECIAL_FILE_REJECTED", "A non-regular quarantine entry is present.", "Reject this quarantine; devices, sockets and FIFOs are never scanned or promoted.", nil)
		}
	}
	return nil
}

func addRegularFile(ctx context.Context, directoryFD int, name, relative string, before unix.Stat_t, limits InventoryLimits, classifier MIMEClassifier, inventory *Inventory) error {
	if before.Size < 0 || uint64(before.Size) > limits.MaxInputBytes-inventory.TotalBytes {
		return scanError("SCAN_LIMIT_REACHED", "Quarantine content exceeds the inventory byte limit.", "Reduce the selected content and restart the workflow.", nil)
	}
	if uint64(len(inventory.Entries)) >= limits.MaxFiles {
		return scanError("SCAN_LIMIT_REACHED", "Quarantine content exceeds the inventory file-count limit.", "Reduce the selected content and restart the workflow.", nil)
	}
	fd, err := openRelative(directoryFD, name, uint64(unix.O_RDONLY|unix.O_CLOEXEC))
	if err != nil {
		return unsafeOpenError(err)
	}
	file := os.NewFile(uintptr(fd), "quarantine-entry")
	if file == nil {
		unix.Close(fd)
		return scanError("SCAN_TRAVERSAL_FAILED", "A quarantine file descriptor could not be owned safely.", "Destroy the scanner and retry in a fresh session.", nil)
	}
	defer file.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameStat(before, opened) || opened.Nlink != 1 {
		return scanError("SCAN_ENTRY_CHANGED", "A quarantine file changed during inventory.", "Reject this quarantine and repeat the download in a fresh session.", err)
	}
	prefixSize := int64(limits.MaxPrefixBytes)
	if opened.Size < prefixSize {
		prefixSize = opened.Size
	}
	prefix := make([]byte, prefixSize)
	if _, err := io.ReadFull(file, prefix); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		clear(prefix)
		return scanError("SCAN_READ_FAILED", "A quarantine file could not be read completely.", "Reject this quarantine and retry from a fresh download.", err)
	}
	detectedMIME, err := classifier.Classify(ctx, prefix)
	clear(prefix)
	if err != nil || !validMIME(detectedMIME) {
		return scanError("SCAN_TYPE_IDENTIFICATION_FAILED", "A quarantine file type could not be identified safely.", "Reject this quarantine or install the verified scanner classifier.", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return scanError("SCAN_READ_FAILED", "A quarantine file could not be rewound safely.", "Reject this quarantine and retry from a fresh download.", err)
	}
	hasher := sha256.New()
	written, err := io.CopyBuffer(hasher, &contextReader{ctx: ctx, reader: io.LimitReader(file, opened.Size+1)}, make([]byte, 1<<20))
	if err != nil {
		if ctx.Err() != nil {
			return contextScanError(ctx.Err())
		}
		return scanError("SCAN_READ_FAILED", "A quarantine file could not be hashed completely.", "Reject this quarantine and retry from a fresh download.", err)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameStableFile(opened, after) || written != opened.Size {
		return scanError("SCAN_ENTRY_CHANGED", "A quarantine file changed while it was being hashed.", "Reject this quarantine and repeat the download in a fresh session.", err)
	}
	extensionMIME := normalizedExtensionMIME(relative)
	inventory.Entries = append(inventory.Entries, InventoryEntry{
		RelativePath: relative, SizeBytes: uint64(opened.Size), SHA256: hex.EncodeToString(hasher.Sum(nil)),
		DetectedMIME: detectedMIME, ExtensionMIME: extensionMIME,
		ExtensionAgreement: extensionAgrees(extensionMIME, detectedMIME),
		Mode:               uint32(opened.Mode), Device: uint64(opened.Dev), Inode: opened.Ino,
	})
	inventory.TotalBytes += uint64(opened.Size)
	return nil
}

func readDirectoryNames(fd int) ([]string, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(duplicate)
	file := os.NewFile(uintptr(duplicate), "quarantine-directory")
	if file == nil {
		unix.Close(duplicate)
		return nil, errors.New("own directory descriptor")
	}
	entries, readErr := file.ReadDir(-1)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func openRelative(directoryFD int, name string, flags uint64) (int, error) {
	return unix.Openat2(directoryFD, name, &unix.OpenHow{
		Flags: flags,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
}

func unsafeOpenError(err error) error {
	if errors.Is(err, syscall.ENOSYS) {
		return scanError("SCAN_OPENAT2_REQUIRED", "The kernel lacks the required safe traversal operation.", "Use a supported Linux kernel with openat2 and recreate the scanner.", err)
	}
	return scanError("SCAN_ENTRY_CHANGED", "A quarantine entry could not be opened without link traversal.", "Reject this quarantine and retry from a fresh download.", err)
}

func sameStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode
}

func sameStableFile(left, right unix.Stat_t) bool {
	return sameStat(left, right) && left.Nlink == right.Nlink && left.Size == right.Size &&
		left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func validPathComponent(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, "/\x00")
}

func validMIME(value string) bool {
	if value == "" || len(value) > 255 || strings.ContainsAny(value, "\x00\r\n ;") {
		return false
	}
	major, minor, found := strings.Cut(value, "/")
	return found && major != "" && minor != ""
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
