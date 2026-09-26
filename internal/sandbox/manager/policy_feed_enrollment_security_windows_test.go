//go:build windows

package manager

import "github.com/ejpir/gantry/internal/sandbox/localsec"

func checkPrivateEnrollmentKey(path string) error {
	userSID, err := localsec.CurrentUserSID()
	if err != nil {
		return err
	}
	return localsec.VerifyPrivate(path, userSID, false)
}
