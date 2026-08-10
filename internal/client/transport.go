package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	system "github.com/containerd/nerdbox/api/services/system/v1"
	"github.com/containerd/ttrpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ListenRPC creates the host endpoint before a VM starts. vminitd makes one
// dial-back attempt, so callers must establish the listener before boot.
func ListenRPC(rpcSock string) (net.Listener, error) {
	_ = os.Remove(rpcSock)
	listener, err := net.Listen("unix", rpcSock)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", rpcSock, err)
	}
	return listener, nil
}

// AcceptRPCListener accepts vminitd's dial-back and transfers ownership of the
// accepted connection to a ttrpc client. The one-shot listener is always
// closed before this function returns.
func AcceptRPCListener(listener net.Listener, rpcSock string) (*ttrpc.Client, error) {
	defer func() { _ = listener.Close() }()
	fmt.Printf("client: listening on %s — start the VM now\n", rpcSock)
	conn, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("accept: %w", err)
	}
	fmt.Println("client: guest connected over vsock dial-back")
	return ttrpc.NewClient(conn), nil
}

// AcceptRPC creates a listener and waits for vminitd's dial-back. Callers that
// also start the VM should call ListenRPC before boot and AcceptRPCListener
// afterward to avoid racing a fast guest.
func AcceptRPC(rpcSock string) (*ttrpc.Client, error) {
	listener, err := ListenRPC(rpcSock)
	if err != nil {
		return nil, err
	}
	return AcceptRPCListener(listener, rpcSock)
}

// Info queries the guest system service.
func Info(rpcSock string) error {
	client, err := AcceptRPC(rpcSock)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := system.NewTTRPCSystemClient(client).Info(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("Info RPC: %w", err)
	}
	fmt.Println("client: Info RPC succeeded!")
	fmt.Printf("  vminitd version: %s\n", response.Version)
	fmt.Printf("  kernel:          %s\n", response.KernelVersion)
	return nil
}
