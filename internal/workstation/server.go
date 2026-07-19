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
)

type Config struct {
	Root              string
	MaxFileBytes      uint64
	MaxWorkspaceBytes uint64
}

type Server struct {
	privatevmv1.UnimplementedWorkstationGuestServiceServer
	inboxDir  string
	exportDir string
	maxFile   uint64
	maxTotal  uint64
	key       [32]byte

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
	path   string
	size   uint64
	digest [32]byte
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
	inbox := filepath.Join(config.Root, "Inbox")
	export := filepath.Join(config.Root, "Export")
	for _, directory := range []string{config.Root, inbox, export} {
		resolved, err := filepath.EvalSymlinks(directory)
		info, statErr := os.Lstat(directory)
		if err != nil || statErr != nil || resolved != directory || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("workspace directories must exist without symbolic links")
		}
	}
	server := &Server{inboxDir: inbox, exportDir: export, maxFile: maxFile, maxTotal: maxTotal,
		verified: make(map[string]receipt), sent: make(map[string]receipt)}
	if _, err := rand.Read(server.key[:]); err != nil {
		return nil, errors.New("workspace output identity key could not be generated")
	}
	return server, nil
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
	partialName := "." + begin.GetTransferId() + ".partial"
	partialPath := filepath.Join(server.inboxDir, partialName)
	file, err := openExclusiveAt(server.inboxDir, partialName)
	if err != nil {
		return workspaceError(codes.AlreadyExists, "IMPORT_STAGING_CONFLICT", "A volatile import staging name already exists.", "Discard the incomplete import and retry with a fresh transfer identifier.", err)
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(partialPath)
		}
	}()
	receiver, err := transfer.NewReceiver(header, server.maxFile, file)
	if err != nil {
		return transferFailure("TRANSFER_DESCRIPTOR_INVALID", err)
	}
	var sequence, offset uint64
	for {
		if err := stream.Context().Err(); err != nil {
			return workspaceError(codes.Canceled, "TRANSFER_CANCELED", "The import was canceled before verification.", "Retry the import; partial bytes were removed.", err)
		}
		frame, err := stream.Recv()
		if err != nil {
			return workspaceError(codes.InvalidArgument, "TRANSFER_INCOMPLETE", "The import ended before its verified final frame.", "Retry the complete import; partial bytes were removed.", err)
		}
		if chunk := frame.GetChunk(); chunk != nil {
			if chunk.GetSequence() != sequence {
				return transferFailure("TRANSFER_SEQUENCE_INVALID", errors.New("non-monotonic transfer sequence"))
			}
			if err := receiver.WriteChunk(offset, chunk.GetData()); err != nil {
				return transferFailure("TRANSFER_CHUNK_INVALID", err)
			}
			offset += uint64(len(chunk.GetData()))
			sequence++
			continue
		}
		end := frame.GetEnd()
		if end == nil || end.GetTotalSize() != header.Size || !validHash(end.GetDigest(), header.SHA256) {
			return transferFailure("TRANSFER_END_INVALID", errors.New("final size or digest does not match descriptor"))
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
		break
	}
	finalPath := filepath.Join(server.inboxDir, header.Name)
	if err := unix.Renameat2(unix.AT_FDCWD, partialPath, unix.AT_FDCWD, finalPath, unix.RENAME_NOREPLACE); err != nil {
		return workspaceError(codes.AlreadyExists, "IMPORT_TARGET_EXISTS", "The Inbox target already exists and was not overwritten.", "Choose a new logical name or discard the existing guest file explicitly.", err)
	}
	if err := syncDirectory(server.inboxDir); err != nil {
		_ = os.Remove(finalPath)
		return transferFailure("TRANSFER_SYNC_FAILED", err)
	}
	keep = true
	return stream.SendAndClose(&privatevmv1.TransferReceipt{TransferId: begin.GetTransferId(), Descriptor_: begin.GetDescriptor_(), ReceiverDigest: protoHash(header.SHA256)})
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
	file, info, err := openRegularNoFollow(selected.path, int64(server.maxFile))
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
	entries, err := os.ReadDir(server.exportDir)
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
		path := filepath.Join(server.exportDir, entry.Name())
		file, info, err := openRegularNoFollow(path, int64(server.maxFile))
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
		files = append(files, exportFile{id: server.outputID(entry.Name()), name: entry.Name(), path: path, size: size, digest: digest})
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

func openExclusiveAt(directory, name string) (*os.File, error) {
	dir, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func openRegularNoFollow(path string, maximum int64) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		_ = file.Close()
		return nil, nil, errors.Join(err, errors.New("unsafe regular file"))
	}
	return file, info, nil
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

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
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
