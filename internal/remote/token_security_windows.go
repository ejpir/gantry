//go:build windows

package remote

import (
	"fmt"
	"os"

	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func secureTokenFile(path string) error {
	return localsec.SecureRegularFile(path)
}

func validateTokenFileSecurity(path string, _ os.FileInfo) error {
	userSID, err := localsec.CurrentUserSID()
	if err != nil {
		return fmt.Errorf("verify token file %s ACL: %w", path, err)
	}
	if err := localsec.VerifyPrivate(path, userSID, false); err != nil {
		return fmt.Errorf("token file %s has an insecure Windows ACL: %w", path, err)
	}
	return nil
}
