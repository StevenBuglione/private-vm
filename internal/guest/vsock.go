package guest

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"
)

type ClientConfig struct {
	CID            uint32
	Port           uint32
	Token          *Token
	MaxMessageSize int
}

func Listen(port uint32) (net.Listener, error) {
	if port == 0 {
		port = DefaultPort
	}
	listener, err := vsock.Listen(port, nil)
	if err != nil {
		return nil, fmt.Errorf("listen on guest AF_VSOCK: %w", err)
	}
	return listener, nil
}

func Dial(config ClientConfig) (*grpc.ClientConn, error) {
	if config.CID < MinimumGuestCID || config.CID > MaximumGuestCID {
		return nil, errors.New("guest VSOCK CID is outside the supported range")
	}
	if config.Port == 0 {
		config.Port = DefaultPort
	}
	if config.Token == nil || config.Token.value == nil {
		return nil, errors.New("guest capability is required")
	}
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = DefaultMaxMessageSize
	}
	if config.MaxMessageSize < 1<<20 || config.MaxMessageSize > MaximumMessageSize {
		return nil, errors.New("guest gRPC message bound must be between 1 MiB and 16 MiB")
	}

	connection, err := grpc.NewClient(
		"passthrough:///private-vm-guest",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return dialVSOCK(ctx, config.CID, config.Port)
		}),
		grpc.WithTransportCredentials(VSOCKTransportCredentials()),
		grpc.WithMaxHeaderListSize(MaxHeaderListSize),
		grpc.WithChainUnaryInterceptor(config.Token.UnaryClientInterceptor()),
		grpc.WithChainStreamInterceptor(config.Token.StreamClientInterceptor()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(config.MaxMessageSize),
			grpc.MaxCallSendMsgSize(config.MaxMessageSize),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create guest VSOCK client: %w", err)
	}
	return connection, nil
}
