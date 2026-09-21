//go:build !linux && !darwin

package manager

import (
	"context"
	"errors"
)

func ensureDefaultManager(context.Context, string) (ensureResult, error) {
	return ensureResult{}, errors.New("automatic local manager startup currently requires Linux or macOS; start gantry serve explicitly on this platform")
}
