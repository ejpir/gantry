//go:build darwin

package selfupdate

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

var hypervisorEntitlement = regexp.MustCompile(`(?s)<key>\s*com\.apple\.security\.hypervisor\s*</key>\s*<true\s*/>`)

func validatePlatformSignature(path string) error {
	if output, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", path).CombinedOutput(); err != nil {
		return fmt.Errorf("invalid macOS code signature: %w: %s", err, strings.TrimSpace(string(output)))
	}
	output, err := exec.Command("/usr/bin/codesign", "-d", "--entitlements", ":-", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("read macOS entitlements: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if !hypervisorEntitlement.Match(output) {
		return fmt.Errorf("release binary lacks an enabled com.apple.security.hypervisor entitlement")
	}
	return nil
}
