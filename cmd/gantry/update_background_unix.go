//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func startBackgroundUpdateCheck() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.Command(executable, "_update-check")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}
