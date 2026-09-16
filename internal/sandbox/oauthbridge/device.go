package oauthbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ejpir/gantry/internal/oauthprovider"
)

// DeviceAuthorization contains a host-only device code and public browser
// instructions. Only VerificationURI/UserCode may be returned to the guest.
type DeviceAuthorization struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int64  `json:"expires_in"`
	Interval        int64  `json:"interval"`
}

func BeginDeviceAuthorization(ctx context.Context, spec CustodySpec) (DeviceAuthorization, error) {
	grant := map[string]string{"client_id": spec.ClientID}
	if spec.Scope != "" {
		grant["scope"] = spec.Scope
	}
	if spec.Resource != "" {
		grant["resource"] = spec.Resource
	}
	raw, err := postGrant(ctx, spec.DeviceAuthorizationURL, grant, spec.ExchangeEncoding)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	var device DeviceAuthorization
	if err := json.Unmarshal(raw, &device); err != nil {
		return device, fmt.Errorf("invalid device authorization JSON")
	}
	if device.DeviceCode == "" || device.UserCode == "" || len(device.DeviceCode) > 4096 || len(device.UserCode) > 256 ||
		device.ExpiresIn <= 0 || device.ExpiresIn > 3600 || device.Interval < 0 || device.Interval > 3600 {
		return DeviceAuthorization{}, fmt.Errorf("invalid device authorization response")
	}
	if err := oauthprovider.ValidateEndpoint(device.VerificationURI); err != nil {
		return DeviceAuthorization{}, fmt.Errorf("invalid device verification URI")
	}
	if device.Interval == 0 {
		device.Interval = 5
	} // RFC 8628 default
	return device, nil
}

// PollDeviceAuthorization follows RFC 8628, including interval increases on
// slow_down. Error bodies and the device code are never returned to the guest.
func PollDeviceAuthorization(ctx context.Context, spec CustodySpec, device DeviceAuthorization) (TokenResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(device.ExpiresIn)*time.Second)
	defer cancel()
	interval := time.Duration(device.Interval) * time.Second
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return TokenResponse{}, fmt.Errorf("device authorization expired or cancelled")
		case <-timer.C:
		}
		tok, err := postToken(ctx, spec, map[string]string{
			"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
			"device_code": device.DeviceCode, "client_id": spec.ClientID,
		}, spec.ExchangeEncoding, false)
		if err == nil {
			return tok, nil
		}
		var endpointErr *TokenEndpointError
		if errors.As(err, &endpointErr) {
			switch endpointErr.Code {
			case "authorization_pending":
				continue
			case "slow_down":
				interval += 5 * time.Second
				continue
			}
			if endpointErr.StatusCode < 500 {
				return TokenResponse{}, err
			}
		}
		// Transport failures/server outages retry more slowly, bounded by the
		// device lifetime; no busy loop if the provider is unavailable.
		interval = max(interval, min(interval*2, time.Minute))
	}
}
