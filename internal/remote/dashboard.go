package remote

import (
	"context"
	"errors"
	"net/http"
	"strings"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/packetcapture"
)

// DashboardSnapshot returns the manager host's complete non-secret dashboard
// read model and form limits. Rows are unscoped on the wire; the caller tags
// them with the profile that authenticated the response.
func (c *Client) DashboardSnapshot(ctx context.Context) (dashboardapi.HostSnapshot, error) {
	var snapshot dashboardapi.HostSnapshot
	err := c.do(ctx, http.MethodGet, "/v1/dashboard", nil, false, &snapshot)
	return snapshot, err
}

// DashboardAction invokes one member of the manager's closed dashboard action
// union. Credential-bearing payloads are write-only and never returned.
func (c *Client) DashboardAction(ctx context.Context, request dashboardapi.ActionRequest) (dashboardapi.ActionResult, error) {
	var result dashboardapi.ActionResult
	err := c.do(ctx, http.MethodPost, "/v1/dashboard/actions", request, false, &result)
	if err == nil {
		return result, nil
	}
	// A hostile or buggy manager must not turn write-only action values into a
	// client diagnostic. Redact both live sandbox secrets and registry logins.
	var values []string
	if request.Secret != nil && request.Secret.Value != "" {
		values = append(values, request.Secret.Value.Raw())
	}
	if request.Registry != nil && request.Registry.Secret != "" {
		values = append(values, request.Registry.Secret.Raw())
	}
	for _, value := range values {
		if value == "" || !strings.Contains(err.Error(), value) {
			continue
		}
		var apiErr *Error
		if errors.As(err, &apiErr) {
			apiErr.Message = strings.ReplaceAll(apiErr.Message, value, "[redacted]")
			apiErr.OperationID = strings.ReplaceAll(apiErr.OperationID, value, "[redacted]")
		} else {
			err = errors.New(strings.ReplaceAll(err.Error(), value, "[redacted]"))
		}
	}
	return result, err
}

func (c *Client) CapturePackets(ctx context.Context, name string, request packetcapture.Request) (packetcapture.Snapshot, error) {
	var snapshot packetcapture.Snapshot
	err := c.do(ctx, http.MethodPost, "/v1/dashboard/packets/"+name, request, false, &snapshot)
	return snapshot, err
}
