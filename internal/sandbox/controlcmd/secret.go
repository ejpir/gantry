package controlcmd

import (
	"fmt"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/secret"
)

// SetSecret updates an in-memory secret through the running daemon. Values are
// intentionally never persisted by an offline client.
func SetSecret(name, secretName string, value secret.Value) error {
	if err := layout.ValidateName(name); err != nil {
		return err
	}
	if err := secret.ValidateName(secretName); err != nil {
		return err
	}
	if _, alive := layout.PID(name); !alive {
		return fmt.Errorf("sandbox %q is not running", name)
	}
	return secretControlRPC(name, "secret.set", secretName, value)
}

// RemoveSecret revokes through the daemon when running or updates the saved
// configuration under the launch lock when stopped.
func RemoveSecret(name, secretName string) error {
	if err := layout.ValidateName(name); err != nil {
		return err
	}
	if err := secret.ValidateName(secretName); err != nil {
		return err
	}
	return mutateRunningOrStopped(name, func() error {
		return secretControlRPC(name, "secret.remove", secretName, "")
	}, func() error {
		store, err := config.LoadConfigStore(layout.Dir(name))
		if err != nil {
			return err
		}
		return store.SetSecretName(secretName, false)
	})
}

func secretControlRPC(name, op, secretName string, value secret.Value) error {
	req := controlproto.Request{
		Op: op,
		ID: controlproto.NewRequestID("secret"),
		Secret: &controlproto.SecretRequest{
			Name:  secretName,
			Value: value,
		},
	}
	resp, err := controlproto.Call[controlproto.SecretResponse](name, req)
	if err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "secret update failed"
		}
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}
