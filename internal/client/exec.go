package client

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/containerd/ttrpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

var sessionTaskSequence atomic.Uint64

// nextSessionTaskID remains unique when several host sessions arrive within
// one guest clock tick. That is common under WHPX: Linux's early wall clock
// can return the same UnixNano value to concurrent goroutines.
func nextSessionTaskID(containerID string) string {
	return fmt.Sprintf("%s-session-%d-%d", containerID, time.Now().UnixNano(), sessionTaskSequence.Add(1))
}

const guestSystemService = "containerd.vminitd.services.system.v1.System"

// SyncGuest asks the trusted vminitd system service to flush every guest
// filesystem. It never resolves or executes a path from the workload image.
func SyncGuest(client *ttrpc.Client, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var response emptypb.Empty
	if err := client.Call(ctx, guestSystemService, "Sync", &emptypb.Empty{}, &response); err != nil {
		return fmt.Errorf("guest system sync: %w", err)
	}
	return nil
}
