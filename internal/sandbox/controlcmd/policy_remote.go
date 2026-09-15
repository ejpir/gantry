package controlcmd

import (
	"fmt"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// SetOrganizationPolicy is shared by the local CLI and HTTP manager. An
// uploaded snapshot is verified here, never trusted just because a client
// says it verified it. Running sandboxes reconcile through their daemon;
// stopped sandboxes update the saved snapshot under the launch lock.
func SetOrganizationPolicy(name string, snapshot *policy.Config) error {
	if err := layout.ValidateName(name); err != nil {
		return err
	}
	if _, err := policy.New(snapshot, nil); err != nil {
		return err
	}
	return mutateRunningOrStopped(name, func() error {
		response, err := controlproto.CallWithTimeout[controlproto.OrganizationPolicyResponse](name, controlproto.Request{
			Op: "policy.set", ID: controlproto.NewRequestID("policy"),
			Policy: &controlproto.OrganizationPolicyRequest{Snapshot: policy.CloneConfig(snapshot), Clear: snapshot == nil},
		}, controlproto.ConfigureTimeout)
		if err != nil {
			return err
		}
		if !response.OK {
			return fmt.Errorf("live organization policy: %s", response.Error)
		}
		return nil
	}, func() error {
		store, err := config.LoadConfigStore(layout.Dir(name))
		if err != nil {
			return err
		}
		return store.Mutate(func(cfg *config.RunConfig) error {
			if snapshot != nil && cfg.OAuthCustodyEnabled() {
				return fmt.Errorf("organization policy v1 does not support OAuth custody")
			}
			cfg.OrgPolicy = policy.CloneConfig(snapshot)
			return nil
		})
	})
}
