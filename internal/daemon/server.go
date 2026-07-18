package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"google.golang.org/grpc"
)

type ServerOptions struct {
	SocketPath string
	OwnerUID   int
	GroupGID   int
	Service    *Service
	Authorizer Authorizer
}

type Server struct {
	options ServerOptions
	grpc    *grpc.Server
	listen  *net.UnixListener
}

func NewServer(options ServerOptions) (*Server, error) {
	if options.Service == nil || options.Service.Sessions == nil {
		return nil, errors.New("daemon service and session manager are required")
	}
	if !filepath.IsAbs(options.SocketPath) || filepath.Base(options.SocketPath) != "control.sock" {
		return nil, errors.New("control socket must be an absolute control.sock path")
	}
	if options.OwnerUID < 0 || options.GroupGID < 0 {
		return nil, errors.New("control socket owner and group are required")
	}
	server := grpc.NewServer(
		grpc.Creds(NewUnixPeerCredentials()),
		grpc.MaxRecvMsgSize(4<<20),
		grpc.MaxSendMsgSize(4<<20),
		grpc.MaxConcurrentStreams(64),
		grpc.UnaryInterceptor(options.Authorizer.UnaryInterceptor),
		grpc.StreamInterceptor(options.Authorizer.StreamInterceptor),
	)
	privatevmv1.RegisterPrivateVMDaemonServiceServer(server, options.Service)
	return &Server{options: options, grpc: server}, nil
}

func (s *Server) Listen() error {
	if s.listen != nil {
		return errors.New("daemon server is already listening")
	}
	parent := filepath.Dir(s.options.SocketPath)
	if err := verifySocketParent(parent); err != nil {
		return err
	}
	if err := removeStaleSocket(s.options.SocketPath, uint32(s.options.OwnerUID)); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.options.SocketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen on control socket: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = listener.Close()
			_ = os.Remove(s.options.SocketPath)
		}
	}()
	if err := os.Chown(s.options.SocketPath, s.options.OwnerUID, s.options.GroupGID); err != nil {
		return fmt.Errorf("set control socket ownership: %w", err)
	}
	if err := os.Chmod(s.options.SocketPath, 0o660); err != nil {
		return fmt.Errorf("set control socket permissions: %w", err)
	}
	s.listen = listener
	cleanup = false
	return nil
}

func (s *Server) Serve() error {
	if s.listen == nil {
		return errors.New("daemon server is not listening")
	}
	if err := s.grpc.Serve(s.listen); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve private-vmd RPC: %w", err)
	}
	return nil
}

func (s *Server) Stop() {
	s.grpc.Stop()
	if s.listen != nil {
		_ = s.listen.Close()
	}
	_ = os.Remove(s.options.SocketPath)
}

func (s *Server) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.grpc.Stop()
		<-done
		if s.listen != nil {
			_ = s.listen.Close()
		}
		_ = os.Remove(s.options.SocketPath)
		return ctx.Err()
	}
	if s.listen != nil {
		_ = s.listen.Close()
	}
	_ = os.Remove(s.options.SocketPath)
	return nil
}

func verifySocketParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect control socket directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("control socket parent is not a real directory")
	}
	if info.Mode().Perm()&0o002 != 0 {
		return errors.New("control socket parent is world-writable")
	}
	return nil
}

func removeStaleSocket(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing control socket: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != ownerUID {
		return errors.New("refusing to replace unexpected control socket path")
	}
	connection, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return errors.New("refusing to replace an active control socket")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale control socket: %w", err)
	}
	return nil
}
