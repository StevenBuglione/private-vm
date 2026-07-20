// Package workstation implements the role-specific guest workspace boundary.
package workstation

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/transfer"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultMaxFileBytes      = uint64(8 << 30)
	defaultMaxWorkspaceBytes = uint64(16 << 30)
	maxWorkspaceEntries      = 1024
	maxWorkspaceFrames       = defaultMaxFileBytes/transfer.DefaultMaxChunk + 2
)

type Config struct {
	Root              string
	MaxFileBytes      uint64
	MaxWorkspaceBytes uint64
}

var (
	ErrWorkspaceRoot   = errors.New("workspace root must exist without symbolic links")
	ErrWorkspaceInbox  = errors.New("workspace Inbox must exist without symbolic links")
	ErrWorkspaceExport = errors.New("workspace Export must exist without symbolic links")
)

type Server struct {
	privatevmv1.UnimplementedWorkstationGuestServiceServer
	inbox    *pinnedDirectory
	export   *pinnedDirectory
	maxFile  uint64
	maxTotal uint64
	key      [32]byte

	mu       sync.Mutex
	verified map[string]receipt
	sent     map[string]receipt
}

type receipt struct {
	digest [32]byte
	size   uint64
}

type exportFile struct {
	id     string
	name   string
	size   uint64
	digest [32]byte
}

type pinnedDirectory struct {
	mu     sync.Mutex
	path   string
	fd     int
	device uint64
	inode  uint64
	closed bool
}

type directoryLease struct {
	path   string
	fd     int
	device uint64
	inode  uint64
}

func New(config Config) (*Server, error) {
	if !filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root || config.Root == "/" {
		return nil, errors.New("workspace root must be a clean absolute path")
	}
	maxFile := config.MaxFileBytes
	if maxFile == 0 {
		maxFile = defaultMaxFileBytes
	}
	maxTotal := config.MaxWorkspaceBytes
	if maxTotal == 0 {
		maxTotal = defaultMaxWorkspaceBytes
	}
	if maxFile == 0 || maxTotal < maxFile {
		return nil, errors.New("workspace byte limits are invalid")
	}
	rootFD, err := openDirectoryPath(config.Root)
	if err != nil {
		return nil, errors.Join(ErrWorkspaceRoot, err)
	}
	defer unix.Close(rootFD)
	inbox, err := pinDirectoryAt(rootFD, filepath.Join(config.Root, "Inbox"), "Inbox")
	if err != nil {
		return nil, errors.Join(ErrWorkspaceInbox, err)
	}
	export, err := pinDirectoryAt(rootFD, filepath.Join(config.Root, "Export"), "Export")
	if err != nil {
		_ = inbox.close()
		return nil, errors.Join(ErrWorkspaceExport, err)
	}
	server := &Server{inbox: inbox, export: export, maxFile: maxFile, maxTotal: maxTotal,
		verified: make(map[string]receipt), sent: make(map[string]receipt)}
	if _, err := rand.Read(server.key[:]); err != nil {
		_ = server.Close(context.Background())
		return nil, errors.New("workspace output identity key could not be generated")
	}
	return server, nil
}

// Close releases the pinned workspace directory descriptors. Guestd calls it
// only after the gRPC server has stopped accepting role requests.
func (server *Server) Close(context.Context) error {
	if server == nil {
		return nil
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	clear(server.key[:])
	return errors.Join(server.inbox.close(), server.export.close())
}

func (server *Server) ImportFile(stream privatevmv1.WorkstationGuestService_ImportFileServer) (returnedErr error) {
	first, err := stream.Recv()
	if err != nil || first.GetBegin() == nil {
		return workspaceError(codes.InvalidArgument, "TRANSFER_BEGIN_REQUIRED", "The import must begin with one bounded descriptor.", "Retry the single-file import from its first frame.", err)
	}
	begin := first.GetBegin()
	if !validOpaqueID(begin.GetTransferId()) {
		return workspaceError(codes.InvalidArgument, "TRANSFER_ID_INVALID", "The transfer identifier is malformed.", "Retry through the private-vm host daemon.", nil)
	}
	header, err := descriptorHeader(begin.GetDescriptor_(), server.maxFile)
	if err != nil {
		return err
	}
	inbox, err := server.inbox.lease()
	if err == nil {
		err = inbox.verifyPath()
	}
	if err != nil {
		if inbox != nil {
			_ = inbox.close()
		}
		return workspaceError(codes.FailedPrecondition, "WORKSPACE_INBOX_CHANGED", "The pinned Inbox directory identity changed.", "Restore the original guest Inbox directory or recreate the workstation.", err)
	}
	defer inbox.close()
	partialName := "." + begin.GetTransferId() + ".partial"
	file, err := openExclusiveAt(inbox.fd, partialName)
	if err != nil {
		return workspaceError(codes.AlreadyExists, "IMPORT_STAGING_CONFLICT", "A volatile import staging name already exists.", "Discard the incomplete import and retry with a fresh transfer identifier.", err)
	}
	keep, published := false, false
	defer func() {
		_ = file.Close()
		if !keep {
			name := partialName
			if published {
				name = header.Name
			}
			_ = unix.Unlinkat(inbox.fd, name, 0)
			_ = unix.Fsync(inbox.fd)
		}
	}()
	receiver, err := transfer.NewReceiver(header, server.maxFile, file)
	if err != nil {
		return transferFailure("TRANSFER_DESCRIPTOR_INVALID", err)
	}
	var sequence, offset uint64
	for frameCount := uint64(1); frameCount < maxWorkspaceFrames; frameCount++ {
		if err := stream.Context().Err(); err != nil {
			return workspaceContextError(err)
		}
		frame, err := stream.Recv()
		if err != nil {
			if contextErr := stream.Context().Err(); contextErr != nil {
				return workspaceContextError(contextErr)
			}
			return workspaceError(codes.InvalidArgument, "TRANSFER_INCOMPLETE", "The import ended before its verified final frame.", "Retry the complete import; partial bytes were removed.", err)
		}
		if chunk := frame.GetChunk(); chunk != nil {
			if chunk.GetSequence() != sequence {
				clear(chunk.Data)
				return transferFailure("TRANSFER_SEQUENCE_INVALID", errors.New("non-monotonic transfer sequence"))
			}
			if len(chunk.GetData()) == 0 || len(chunk.GetData()) > transfer.DefaultMaxChunk {
				clear(chunk.Data)
				return transferFailure("TRANSFER_CHUNK_INVALID", errors.New("empty or oversized transfer chunk"))
			}
			chunkBytes := uint64(len(chunk.GetData()))
			if err := receiver.WriteChunk(offset, chunk.GetData()); err != nil {
				clear(chunk.Data)
				return transferFailure("TRANSFER_CHUNK_INVALID", err)
			}
			clear(chunk.Data)
			offset += chunkBytes
			sequence++
			continue
		}
		end := frame.GetEnd()
		if end == nil || end.GetTotalSize() != header.Size || !validHash(end.GetDigest(), header.SHA256) {
			return transferFailure("TRANSFER_END_INVALID", errors.New("final size or digest does not match descriptor"))
		}
		trailing, trailingErr := stream.Recv()
		clearTransferFrame(trailing)
		if trailing != nil || !errors.Is(trailingErr, io.EOF) {
			if contextErr := stream.Context().Err(); contextErr != nil {
				return workspaceContextError(contextErr)
			}
			return transferFailure("TRANSFER_TRAILING_FRAME", errors.New("transfer continued after its final frame"))
		}
		if err := receiver.Finish(); err != nil {
			return transferFailure("TRANSFER_DIGEST_MISMATCH", err)
		}
		if err := file.Sync(); err != nil {
			return transferFailure("TRANSFER_SYNC_FAILED", err)
		}
		if err := file.Close(); err != nil {
			return transferFailure("TRANSFER_SYNC_FAILED", err)
		}
		if err := inbox.verifyPath(); err != nil {
			return workspaceError(codes.FailedPrecondition, "WORKSPACE_INBOX_CHANGED", "The pinned Inbox directory identity changed.", "Restore the original guest Inbox directory or recreate the workstation.", err)
		}
		if err := unix.Renameat2(inbox.fd, partialName, inbox.fd, header.Name, unix.RENAME_NOREPLACE); err != nil {
			return workspaceError(codes.AlreadyExists, "IMPORT_TARGET_EXISTS", "The Inbox target already exists and was not overwritten.", "Choose a new logical name or discard the existing guest file explicitly.", err)
		}
		published = true
		if err := unix.Fsync(inbox.fd); err != nil {
			return transferFailure("TRANSFER_SYNC_FAILED", err)
		}
		if err := inbox.verifyPath(); err != nil {
			return workspaceError(codes.FailedPrecondition, "WORKSPACE_INBOX_CHANGED", "The pinned Inbox directory identity changed.", "Restore the original guest Inbox directory or recreate the workstation.", err)
		}
		receipt := &privatevmv1.TransferReceipt{TransferId: begin.GetTransferId(), Descriptor_: begin.GetDescriptor_(), ReceiverDigest: protoHash(header.SHA256)}
		if err := stream.SendAndClose(receipt); err != nil {
			return err
		}
		keep = true
		return nil
	}
	return workspaceError(codes.ResourceExhausted, "TRANSFER_FRAME_LIMIT", "The import exceeded its bounded frame count.", "Retry with the documented chunk size; partial bytes were removed.", nil)
}

func (server *Server) GetWorkspaceState(ctx context.Context, _ *privatevmv1.WorkspaceStateRequest) (*privatevmv1.WorkspaceState, error) {
	return server.workspaceState(ctx)
}

func (server *Server) ListExportFiles(ctx context.Context, _ *privatevmv1.WorkspaceStateRequest) (*privatevmv1.WorkspaceState, error) {
	return server.workspaceState(ctx)
}

func (server *Server) workspaceState(ctx context.Context) (*privatevmv1.WorkspaceState, error) {
	files, err := server.inventory(ctx)
	if err != nil {
		return nil, err
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	state := "CLEAN"
	entries := make([]*privatevmv1.WorkspaceEntry, 0, len(files))
	changed := false
	unexported := false
	for _, file := range files {
		verified, ok := server.verified[file.id]
		isChanged := ok && (verified.size != file.size || verified.digest != file.digest)
		isExported := ok && !isChanged
		changed = changed || isChanged
		unexported = unexported || !isExported
		entries = append(entries, &privatevmv1.WorkspaceEntry{OutputId: file.id, SizeBytes: file.size, Exported: isExported, ChangedSinceExport: isChanged})
	}
	if changed {
		state = "CHANGED"
	} else if unexported {
		state = "UNEXPORTED"
	} else if len(files) > 0 {
		state = "READY"
	}
	return &privatevmv1.WorkspaceState{State: state, Entries: entries}, nil
}

func (server *Server) ExportFile(request *privatevmv1.GuestExportFileRequest, stream privatevmv1.WorkstationGuestService_ExportFileServer) error {
	files, err := server.inventory(stream.Context())
	if err != nil {
		return err
	}
	var selected *exportFile
	for index := range files {
		if files[index].id == request.GetOutputId() {
			selected = &files[index]
			break
		}
	}
	if selected == nil {
		return workspaceError(codes.NotFound, "WORKSPACE_OUTPUT_NOT_FOUND", "The selected volatile output no longer exists.", "Refresh the workspace inventory and select one current output.", nil)
	}
	export, err := server.export.lease()
	if err != nil {
		return workspaceError(codes.FailedPrecondition, "WORKSPACE_EXPORT_CHANGED", "The pinned Export directory is unavailable.", "Restore the original guest Export directory or recreate the workstation.", err)
	}
	defer export.close()
	if err := export.verifyPath(); err != nil {
		return workspaceError(codes.FailedPrecondition, "WORKSPACE_EXPORT_CHANGED", "The pinned Export directory identity changed.", "Restore the original guest Export directory or recreate the workstation.", err)
	}
	file, info, err := openRegularAt(export.fd, selected.name, int64(server.maxFile))
	if err != nil || uint64(info.Size()) != selected.size {
		return workspaceError(codes.FailedPrecondition, "WORKSPACE_OUTPUT_CHANGED", "The output changed before export began.", "Refresh the inventory and review the changed output.", err)
	}
	defer file.Close()
	begin := &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{TransferId: selected.id,
		Descriptor_: &privatevmv1.FileDescriptor{LogicalName: selected.name, SizeBytes: selected.size, Digest: protoHash(selected.digest)}}}}
	if err := stream.Send(begin); err != nil {
		return err
	}
	buffer := make([]byte, transfer.DefaultMaxChunk)
	var sequence uint64
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			data := append([]byte(nil), buffer[:count]...)
			if err := stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Sequence: sequence, Data: data}}}); err != nil {
				clear(data)
				return err
			}
			clear(data)
			sequence++
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return transferFailure("TRANSFER_READ_FAILED", readErr)
		}
	}
	if err := stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{TotalSize: selected.size, Digest: protoHash(selected.digest)}}}); err != nil {
		return err
	}
	if err := export.verifyPath(); err != nil {
		return workspaceError(codes.FailedPrecondition, "WORKSPACE_EXPORT_CHANGED", "The pinned Export directory identity changed during export.", "Restore the original guest Export directory or recreate the workstation.", err)
	}
	server.mu.Lock()
	server.sent[selected.id] = receipt{digest: selected.digest, size: selected.size}
	server.mu.Unlock()
	return nil
}

func (server *Server) MarkExportVerified(ctx context.Context, request *privatevmv1.MarkExportVerifiedRequest) (*privatevmv1.WorkspaceState, error) {
	files, err := server.inventory(ctx)
	if err != nil {
		return nil, err
	}
	var current *exportFile
	for index := range files {
		if files[index].id == request.GetOutputId() {
			current = &files[index]
			break
		}
	}
	if current == nil || !validHash(request.GetDigest(), current.digest) {
		return nil, workspaceError(codes.FailedPrecondition, "EXPORT_VERIFICATION_MISMATCH", "The host verification digest does not match the current guest output.", "Do not discard the workspace; export and verify the current bytes again.", nil)
	}
	server.mu.Lock()
	sent, ok := server.sent[current.id]
	if !ok || sent.digest != current.digest || sent.size != current.size {
		server.mu.Unlock()
		return nil, workspaceError(codes.FailedPrecondition, "EXPORT_NOT_STREAMED", "The current output was not completely streamed before verification.", "Export the selected output completely, then verify its received digest.", nil)
	}
	server.verified[current.id] = sent
	server.mu.Unlock()
	return server.workspaceState(ctx)
}

func (server *Server) ShowNetworkWarning(context.Context, *privatevmv1.NetworkWarningRequest) (*privatevmv1.Empty, error) {
	return &privatevmv1.Empty{}, nil
}

func (server *Server) inventory(ctx context.Context) ([]exportFile, error) {
	export, err := server.export.lease()
	if err != nil {
		return nil, workspaceError(codes.FailedPrecondition, "WORKSPACE_EXPORT_CHANGED", "The pinned Export directory is unavailable.", "Restore the original guest Export directory or recreate the workstation.", err)
	}
	defer export.close()
	if err := export.verifyPath(); err != nil {
		return nil, workspaceError(codes.FailedPrecondition, "WORKSPACE_EXPORT_CHANGED", "The pinned Export directory identity changed.", "Restore the original guest Export directory or recreate the workstation.", err)
	}
	entries, err := readDirectoryEntries(export.fd)
	if err != nil || len(entries) > maxWorkspaceEntries {
		return nil, workspaceError(codes.FailedPrecondition, "WORKSPACE_INVENTORY_FAILED", "The Export directory could not be inventoried within its bounds.", "Remove unsupported entries inside the guest and retry.", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	files := make([]exportFile, 0, len(entries))
	var total uint64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, workspaceError(codes.Canceled, "WORKSPACE_INVENTORY_CANCELED", "Workspace inventory was canceled.", "Retry after the current operation finishes.", err)
		}
		header := transfer.Header{Name: entry.Name()}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || header.Validate(server.maxFile) != nil {
			return nil, workspaceError(codes.FailedPrecondition, "WORKSPACE_ENTRY_UNSAFE", "Export contains a directory, link, or unsafe name.", "Keep only bounded regular files directly inside Export.", nil)
		}
		file, info, err := openRegularAt(export.fd, entry.Name(), int64(server.maxFile))
		if err != nil {
			return nil, workspaceError(codes.FailedPrecondition, "WORKSPACE_ENTRY_UNSAFE", "Export contains a non-regular or oversized entry.", "Keep only bounded regular files directly inside Export.", err)
		}
		digest, hashErr := hashFile(ctx, file, server.maxFile)
		closeErr := file.Close()
		if hashErr != nil || closeErr != nil {
			return nil, workspaceError(codes.Internal, "WORKSPACE_HASH_FAILED", "An output could not be hashed completely.", "Retry before stopping the workstation.", errors.Join(hashErr, closeErr))
		}
		size := uint64(info.Size())
		if size > server.maxTotal-total {
			return nil, workspaceError(codes.ResourceExhausted, "WORKSPACE_CAPACITY_EXCEEDED", "Export exceeds the bounded workspace capacity.", "Remove unneeded guest outputs before retrying.", nil)
		}
		total += size
		files = append(files, exportFile{id: server.outputID(entry.Name()), name: entry.Name(), size: size, digest: digest})
	}
	if err := export.verifyPath(); err != nil {
		return nil, workspaceError(codes.FailedPrecondition, "WORKSPACE_EXPORT_CHANGED", "The pinned Export directory identity changed during inventory.", "Restore the original guest Export directory or recreate the workstation.", err)
	}
	return files, nil
}

func (server *Server) outputID(name string) string {
	mac := hmac.New(sha256.New, server.key[:])
	_, _ = mac.Write([]byte(name))
	return "output-" + hex.EncodeToString(mac.Sum(nil)[:16])
}

func descriptorHeader(descriptor *privatevmv1.FileDescriptor, maximum uint64) (transfer.Header, error) {
	if descriptor == nil || descriptor.GetDigest() == nil || descriptor.GetDigest().GetAlgorithm() != "sha256" || len(descriptor.GetDigest().GetValue()) != sha256.Size {
		return transfer.Header{}, transferFailure("TRANSFER_DESCRIPTOR_INVALID", errors.New("sha256 descriptor required"))
	}
	var digest [sha256.Size]byte
	copy(digest[:], descriptor.GetDigest().GetValue())
	header := transfer.Header{Name: descriptor.GetLogicalName(), Size: descriptor.GetSizeBytes(), SHA256: digest, MediaType: descriptor.GetDetectedMime()}
	if err := header.Validate(maximum); err != nil {
		return transfer.Header{}, transferFailure("TRANSFER_DESCRIPTOR_INVALID", err)
	}
	return header, nil
}

func validHash(value *privatevmv1.Hash, expected [sha256.Size]byte) bool {
	return value != nil && value.GetAlgorithm() == "sha256" && hmac.Equal(value.GetValue(), expected[:])
}

func protoHash(value [sha256.Size]byte) *privatevmv1.Hash {
	return &privatevmv1.Hash{Algorithm: "sha256", Value: append([]byte(nil), value[:]...)}
}

func validOpaqueID(value string) bool {
	if len(value) < 8 || len(value) > 128 || !strings.HasPrefix(value, "transfer-") {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
			return false
		}
	}
	return true
}

func openDirectoryPath(path string) (int, error) {
	return unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}

func pinDirectoryAt(parentFD int, path, name string) (*pinnedDirectory, error) {
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		// systemd implements the unit's narrow ReadWritePaths with bind mounts,
		// so each explicitly configured endpoint may be a mount boundary. Pin
		// that endpoint once, then keep RESOLVE_NO_XDEV on every operation below
		// its dirfd to prevent later traversal across another filesystem.
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	var identity unix.Stat_t
	if err := unix.Fstat(fd, &identity); err != nil || identity.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return nil, errors.Join(err, errors.New("workspace directory identity is invalid"))
	}
	return &pinnedDirectory{path: path, fd: fd, device: uint64(identity.Dev), inode: identity.Ino}, nil
}

func (directory *pinnedDirectory) lease() (*directoryLease, error) {
	if directory == nil {
		return nil, errors.New("workspace directory is unavailable")
	}
	directory.mu.Lock()
	defer directory.mu.Unlock()
	if directory.closed || directory.fd < 0 {
		return nil, errors.New("workspace directory is closed")
	}
	fd, err := unix.Openat2(directory.fd, ".", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, err
	}
	return &directoryLease{path: directory.path, fd: fd, device: directory.device, inode: directory.inode}, nil
}

func (directory *pinnedDirectory) close() error {
	if directory == nil {
		return nil
	}
	directory.mu.Lock()
	defer directory.mu.Unlock()
	if directory.closed {
		return nil
	}
	directory.closed = true
	err := unix.Close(directory.fd)
	directory.fd = -1
	return err
}

func (lease *directoryLease) close() error {
	if lease == nil || lease.fd < 0 {
		return nil
	}
	err := unix.Close(lease.fd)
	lease.fd = -1
	return err
}

func (lease *directoryLease) verifyPath() error {
	if lease == nil || lease.fd < 0 {
		return errors.New("workspace directory lease is unavailable")
	}
	current, err := openDirectoryPath(lease.path)
	if err != nil {
		return err
	}
	defer unix.Close(current)
	var identity unix.Stat_t
	if err := unix.Fstat(current, &identity); err != nil {
		return err
	}
	if uint64(identity.Dev) != lease.device || identity.Ino != lease.inode {
		return errors.New("workspace directory path was replaced")
	}
	return nil
}

func openExclusiveAt(directoryFD int, name string) (*os.File, error) {
	fd, err := unix.Openat2(directoryFD, name, &unix.OpenHow{
		Flags:   unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Mode:    0o600,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func openRegularAt(directoryFD int, name string, maximum int64) (*os.File, os.FileInfo, error) {
	fd, err := unix.Openat2(directoryFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		_ = file.Close()
		return nil, nil, errors.Join(err, errors.New("unsafe regular file"))
	}
	return file, info, nil
}

func readDirectoryEntries(directoryFD int) ([]os.DirEntry, error) {
	fd, err := unix.Openat2(directoryFD, ".", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), "workspace-directory")
	entries, readErr := directory.ReadDir(-1)
	return entries, errors.Join(readErr, directory.Close())
}

func hashFile(ctx context.Context, file *os.File, maximum uint64) ([sha256.Size]byte, error) {
	hash := sha256.New()
	buffer := make([]byte, transfer.DefaultMaxChunk)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			return [sha256.Size]byte{}, err
		}
		count, err := file.Read(buffer)
		if count > 0 {
			if uint64(count) > maximum-total {
				return [sha256.Size]byte{}, errors.New("file exceeds bound")
			}
			total += uint64(count)
			_, _ = hash.Write(buffer[:count])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return [sha256.Size]byte{}, err
		}
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func clearTransferFrame(frame *privatevmv1.TransferFrame) {
	if frame != nil && frame.GetChunk() != nil {
		clear(frame.GetChunk().Data)
	}
}

func workspaceContextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return workspaceError(codes.DeadlineExceeded, "TRANSFER_TIMEOUT", "The import timed out before verification.", "Retry the import; partial bytes were removed.", err)
	}
	return workspaceError(codes.Canceled, "TRANSFER_CANCELED", "The import was canceled before verification.", "Retry the import; partial bytes were removed.", err)
}

func transferFailure(code string, cause error) error {
	return workspaceError(codes.InvalidArgument, code, "The bounded file transfer failed verification.", "Retry the complete single-file transfer; partial bytes were removed.", cause)
}

func workspaceError(grpcCode codes.Code, code, message, remediation string, cause error) error {
	base := status.New(grpcCode, code+": "+message)
	with, err := base.WithDetails(&privatevmv1.ErrorDetail{Code: code, SafeMessage: message, Remediation: remediation})
	if err == nil {
		base = with
	}
	if cause != nil && (errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded)) {
		return base.Err()
	}
	return base.Err()
}

var _ privatevmv1.WorkstationGuestServiceServer = (*Server)(nil)
