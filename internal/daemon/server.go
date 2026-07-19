package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/vpn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type ServerOptions struct {
	SocketPath                      string
	OwnerUID                        int
	GroupGID                        int
	ConnectionTimeout               time.Duration
	Service                         *Service
	Authorizer                      Authorizer
	testOnlyAllowUntrustedAncestors bool
}

type Server struct {
	options     ServerOptions
	grpc        *grpc.Server
	listen      *net.UnixListener
	serve       net.Listener
	socket      socketIdentity
	connections chan struct{}
	profiles    *vpn.MemoryStore
}

const (
	maximumRPCMessageBytes   = 4 << 20
	maximumRPCHeaderBytes    = 8 << 10
	defaultConnectTimeout    = 10 * time.Second
	maximumDaemonConnections = 32
)

var dialControlSocket = net.DialTimeout

func NewServer(options ServerOptions) (*Server, error) {
	if options.Service == nil || options.Service.Sessions == nil {
		return nil, errors.New("daemon service and session manager are required")
	}
	if !filepath.IsAbs(options.SocketPath) || filepath.Clean(options.SocketPath) != options.SocketPath || filepath.Base(options.SocketPath) != "control.sock" {
		return nil, errors.New("control socket must be an absolute control.sock path")
	}
	if options.OwnerUID < 0 || options.GroupGID < 0 {
		return nil, errors.New("control socket owner and group are required")
	}
	if options.Authorizer.AllowedGroup != uint32(options.GroupGID) {
		return nil, errors.New("control socket group and authorizer group must match")
	}
	if err := options.Service.Config.Validate(); err != nil {
		return nil, errors.New("daemon service configuration is invalid")
	}
	if options.Service.Polkit == nil {
		return nil, errors.New("daemon Polkit adapter is required")
	}
	if options.ConnectionTimeout == 0 {
		options.ConnectionTimeout = defaultConnectTimeout
	}
	if options.ConnectionTimeout < time.Millisecond || options.ConnectionTimeout > defaultConnectTimeout {
		return nil, errors.New("daemon connection timeout is outside supported bounds")
	}
	service := *options.Service
	if service.Profiles == nil {
		service.Profiles = vpn.NewMemoryStore()
	}
	options.Service = &service
	server := grpc.NewServer(
		grpc.Creds(NewUnixPeerCredentials()),
		grpc.MaxRecvMsgSize(maximumRPCMessageBytes),
		grpc.MaxSendMsgSize(maximumRPCMessageBytes),
		grpc.MaxHeaderListSize(maximumRPCHeaderBytes),
		grpc.MaxConcurrentStreams(64),
		grpc.ConnectionTimeout(options.ConnectionTimeout),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     2 * time.Minute,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 30 * time.Second,
		}),
		grpc.ChainUnaryInterceptor(options.Authorizer.UnaryInterceptor, requestContextUnaryInterceptor),
		grpc.StreamInterceptor(options.Authorizer.StreamInterceptor),
	)
	privatevmv1.RegisterPrivateVMDaemonServiceServer(server, options.Service)
	return &Server{
		options: options, grpc: server, profiles: service.Profiles,
		connections: make(chan struct{}, maximumDaemonConnections),
	}, nil
}

func (s *Server) Listen() error {
	if s.listen != nil {
		return errors.New("daemon server is already listening")
	}
	parent := filepath.Dir(s.options.SocketPath)
	if !s.options.testOnlyAllowUntrustedAncestors {
		if err := verifySocketAncestors(parent); err != nil {
			return err
		}
	}
	if err := verifySocketParent(parent, uint32(s.options.OwnerUID), uint32(s.options.GroupGID)); err != nil {
		return err
	}
	if err := removeStaleSocket(s.options.SocketPath, uint32(s.options.OwnerUID), uint32(s.options.GroupGID)); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.options.SocketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen on control socket: %w", err)
	}
	// UnixListener otherwise unlinks by pathname during Close, which could
	// delete a replacement path after an identity swap. Cleanup below is bound
	// to the socket inode we created.
	listener.SetUnlinkOnClose(false)
	cleanup := true
	var created socketIdentity
	defer func() {
		if cleanup {
			_ = listener.Close()
			current, err := inspectSocket(s.options.SocketPath)
			if err == nil && created.ino != 0 && current.sameFile(created) {
				_ = os.Remove(s.options.SocketPath)
			}
		}
	}()
	created, err = inspectSocket(s.options.SocketPath)
	if err != nil {
		return err
	}
	if err := os.Chown(s.options.SocketPath, s.options.OwnerUID, s.options.GroupGID); err != nil {
		return fmt.Errorf("set control socket ownership: %w", err)
	}
	afterChown, err := inspectSocket(s.options.SocketPath)
	if err != nil {
		return err
	}
	if !afterChown.sameObject(created) {
		return errors.New("control socket identity changed during ownership setup")
	}
	created = afterChown
	if err := os.Chmod(s.options.SocketPath, 0o660); err != nil {
		return fmt.Errorf("set control socket permissions: %w", err)
	}
	identity, err := inspectSocket(s.options.SocketPath)
	if err != nil {
		return err
	}
	if identity.uid != uint32(s.options.OwnerUID) || identity.gid != uint32(s.options.GroupGID) || identity.mode != 0o660 {
		return errors.New("control socket ownership or permissions did not match the requested identity")
	}
	if !identity.sameObject(created) {
		return errors.New("control socket identity changed during permission setup")
	}
	s.listen = listener
	s.serve = &admissionListener{Listener: listener, slots: s.connections}
	s.socket = identity
	cleanup = false
	return nil
}

func (s *Server) Serve() error {
	if s.listen == nil {
		return errors.New("daemon server is not listening")
	}
	if err := s.grpc.Serve(s.serve); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve private-vmd RPC: %w", err)
	}
	return nil
}

func (s *Server) Stop() {
	s.grpc.Stop()
	if s.listen != nil {
		_ = s.listen.Close()
	}
	s.removeSocket()
	s.closeProfiles()
}

func (s *Server) Shutdown(ctx context.Context) error {
	defer s.closeProfiles()
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
		s.removeSocket()
		return ctx.Err()
	}
	if s.listen != nil {
		_ = s.listen.Close()
	}
	s.removeSocket()
	return nil
}

func (s *Server) closeProfiles() {
	if s.profiles != nil {
		s.profiles.Close()
	}
}

func (s *Server) removeSocket() {
	if s.socket.ino == 0 {
		return
	}
	current, err := inspectSocket(s.options.SocketPath)
	if err == nil && current.sameFile(s.socket) {
		_ = os.Remove(s.options.SocketPath)
	}
	s.socket = socketIdentity{}
}

func verifySocketParent(path string, ownerUID, groupGID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect control socket directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("control socket parent is not a real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Gid != groupGID {
		return errors.New("control socket parent ownership is invalid")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("control socket parent is group- or world-writable")
	}
	return nil
}

func verifySocketAncestors(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("control socket ancestor path is invalid")
	}
	current := string(filepath.Separator)
	components := strings.Split(strings.TrimPrefix(path, current), current)
	for index, component := range components {
		if component == "" || index == len(components)-1 {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect control socket ancestor: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New("control socket ancestor is not a trusted root-owned directory")
		}
	}
	return nil
}

func removeStaleSocket(path string, ownerUID, groupGID uint32) error {
	before, err := inspectSocket(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if before.uid != ownerUID || before.gid != groupGID {
		return errors.New("refusing to replace unexpected control socket path")
	}
	connection, dialErr := dialControlSocket("unix", path, 250*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return errors.New("refusing to replace an active control socket")
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return errors.New("refusing to replace a control socket after an ambiguous connection failure")
	}
	after, err := inspectSocket(path)
	if err != nil || !after.sameFile(before) {
		return errors.New("control socket identity changed during stale-socket verification")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale control socket: %w", err)
	}
	return nil
}

type socketIdentity struct {
	dev   uint64
	ino   uint64
	uid   uint32
	gid   uint32
	mode  os.FileMode
	mtime int64
}

func inspectSocket(path string) (socketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return socketIdentity{}, fmt.Errorf("inspect control socket: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 {
		return socketIdentity{}, errors.New("control socket path is not a Unix socket")
	}
	return socketIdentity{dev: uint64(stat.Dev), ino: stat.Ino, uid: stat.Uid, gid: stat.Gid, mode: info.Mode().Perm(), mtime: info.ModTime().UnixNano()}, nil
}

func (value socketIdentity) sameFile(other socketIdentity) bool {
	return value.sameObject(other) && value.uid == other.uid && value.gid == other.gid
}

func (value socketIdentity) sameObject(other socketIdentity) bool {
	return value.dev == other.dev && value.ino == other.ino && value.mtime == other.mtime
}

type admissionListener struct {
	net.Listener
	slots chan struct{}
}

func (l *admissionListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &admittedConnection{Conn: connection, release: func() { <-l.slots }}, nil
		default:
			_ = connection.Close()
		}
	}
}

type admittedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *admittedConnection) privateVMUnixConn() *net.UnixConn {
	connection, _ := c.Conn.(*net.UnixConn)
	return connection
}

func (c *admittedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
