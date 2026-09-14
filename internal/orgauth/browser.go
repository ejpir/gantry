package orgauth

import (
	"os/exec"
	"runtime"
)

// OpenBrowser presents an authorization URL without a shell or attached
// diagnostics. Both the CLI and TUI retain a manual URL fallback.
func OpenBrowser(url string) error {
	if _, err := httpsURL(url); err != nil {
		return err
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
