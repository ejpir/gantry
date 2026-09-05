//go:build windows

package secret

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func requireWindowsSecretRejected(t *testing.T, path string) {
	t.Helper()
	if _, err := ParseFile(path); err == nil {
		t.Fatalf("unsafe Windows secret path %q was accepted", path)
	}
}

func TestWindowsSecretOpenRejectsReparsePointsAndHardLinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.env")
	if err := os.WriteFile(target, []byte("TOKEN=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := ParseFile(target)
	if err != nil {
		t.Fatalf("ordinary NTFS secret file: %v", err)
	}
	if got := values["TOKEN"].Raw(); got != "value" {
		t.Fatalf("ordinary NTFS secret value = %q", got)
	}

	t.Run("hard link", func(t *testing.T) {
		link := filepath.Join(root, "hardlink.env")
		if err := os.Link(target, link); err != nil {
			t.Skipf("NTFS hard links unavailable: %v", err)
		}
		requireWindowsSecretRejected(t, link)
	})

	t.Run("final symbolic link", func(t *testing.T) {
		link := filepath.Join(root, "final-link.env")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("Windows symbolic-link privilege unavailable: %v", err)
		}
		requireWindowsSecretRejected(t, link)
	})

	t.Run("intermediate symbolic link", func(t *testing.T) {
		targetDir := filepath.Join(root, "target-dir")
		if err := os.Mkdir(targetDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(targetDir, "nested.env"), []byte("TOKEN=value\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(root, "dir-link")
		if err := os.Symlink(targetDir, linkDir); err != nil {
			t.Skipf("Windows directory-link privilege unavailable: %v", err)
		}
		requireWindowsSecretRejected(t, filepath.Join(linkDir, "nested.env"))
	})

	t.Run("junction", func(t *testing.T) {
		targetDir := filepath.Join(root, "junction-target")
		if err := os.Mkdir(targetDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(targetDir, "nested.env"), []byte("TOKEN=value\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		junction := filepath.Join(root, "junction")
		if err := exec.Command("cmd", "/c", "mklink", "/J", junction, targetDir).Run(); err != nil {
			t.Skipf("Windows junction creation unavailable: %v", err)
		}
		requireWindowsSecretRejected(t, filepath.Join(junction, "nested.env"))
	})
}
