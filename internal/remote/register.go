package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ejpir/gantry/internal/remoteprofile"
)

// ReadCA reads public TLS trust material for either CLI or TUI registration.
func ReadCA(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return "", errors.New("CA must be a regular file of at most 64 KiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil {
		return "", err
	}
	if err := remoteprofile.ValidateCA(string(data)); err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", errors.New("CA bundle is empty")
	}
	return string(data), nil
}

// Register is the shared CLI/TUI add path. Probe verified TLS/authentication
// first, then save without overwriting an existing profile. Tokens never go
// through subprocess argv or the returned result.
func Register(ctx context.Context, profile Profile, token string) (string, error) {
	if err := validateProfile(profile); err != nil {
		return "", err
	}
	if err := ValidateToken(token); err != nil {
		return "", err
	}
	if _, exists, err := Lookup(profile.Name); err != nil {
		return "", err
	} else if exists {
		return "", fmt.Errorf("remote %q already exists; choose a different name", profile.Name)
	}
	client, err := Dial(profile, token)
	if err != nil {
		return "", err
	}
	defer client.Close()
	if _, err := client.Health(ctx); err != nil {
		return "", fmt.Errorf("cannot reach the manager: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := Add(profile, token); err != nil {
		return "", err
	}
	live, _ := client.LiveFingerprint()
	return live, nil
}
