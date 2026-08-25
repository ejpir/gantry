//go:build !linux

package main

import "fmt"

func runUserExists([]string) int {
	fmt.Println("user lookup is only supported inside a Linux gantry guest")
	return 1
}

func runSSHSession([]string) int {
	fmt.Println("ssh sessions are only supported inside a Linux gantry guest")
	return 1
}

func runTCPRelay([]string) int {
	fmt.Println("tcp relay is only supported inside a Linux gantry guest")
	return 1
}

func serveSFTP() error {
	return fmt.Errorf("SFTP is only supported inside a Linux gantry guest")
}
