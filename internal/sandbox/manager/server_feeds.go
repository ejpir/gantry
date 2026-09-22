package manager

import (
	"context"
	"log"
	"path/filepath"

	"github.com/ejpir/gantry/internal/policyfeed"
	"github.com/ejpir/gantry/internal/sandbox/manager/runtimeowner"
)

func startManagerPolicyFeeds(ctx context.Context, service *managerService, owner *runtimeowner.Owner, feeds []*policyfeed.Config, stateDir string, audit *log.Logger) error {
	feedStateDir := filepath.Join(stateDir, "policy-feeds")
	receivers, err := openManagerPolicyFeeds(ctx, service, feeds, feedStateDir, audit)
	if err != nil {
		return err
	}
	owned := make([]runtimeowner.Receiver, len(receivers))
	for i := range receivers {
		owned[i] = receivers[i]
	}
	if err := owner.FeedsReady(owned); err != nil {
		closeManagerPolicyFeeds(receivers)
		return err
	}
	for _, receiver := range receivers {
		if !service.startBackground(func(ctx context.Context) { receiver.Run(ctx) }) {
			return errManagerStopping
		}
	}
	return nil
}

func openManagerPolicyFeeds(ctx context.Context, service *managerService, feeds []*policyfeed.Config, stateDir string, audit *log.Logger) ([]*policyfeed.Receiver, error) {
	receivers := make([]*policyfeed.Receiver, 0, len(feeds))
	for _, feed := range feeds {
		receiver, err := policyfeed.NewReceiver(feed, stateDir, audit, service.applyReceivedOrganizationPolicy)
		if err != nil {
			closeManagerPolicyFeeds(receivers)
			return nil, err
		}
		// Restore the acknowledged signed generation before accepting manager
		// requests. A failed target has already been stopped by the aggregate
		// rollout; retain the receiver so its background loop can retry.
		if err := receiver.Restore(ctx); err != nil && ctx.Err() == nil {
			audit.Printf("policy feed %s: %v", feed.Organization, err)
		}
		receivers = append(receivers, receiver)
	}
	return receivers, nil
}

func closeManagerPolicyFeeds(receivers []*policyfeed.Receiver) {
	for _, receiver := range receivers {
		receiver.Close()
	}
}
