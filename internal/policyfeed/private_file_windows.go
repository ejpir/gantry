//go:build windows

package policyfeed

import (
	"fmt"
	"os"

	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func validatePrivateFile(path string, _ os.FileInfo) error {
	userSID, err := localsec.CurrentUserSID()
	if err != nil {
		return fmt.Errorf("verify client-key ACL: %w", err)
	}
	if err := localsec.VerifyPrivate(path, userSID, false); err != nil {
		return fmt.Errorf("insecure Windows ACL: %w", err)
	}
	return nil
}
