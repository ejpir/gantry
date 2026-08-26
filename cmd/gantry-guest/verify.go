package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

func runVerifySelf(args []string) int {
	if len(args) != 0 {
		return 2
	}
	path, err := os.Executable()
	if err != nil {
		return 1
	}
	file, err := os.Open(path)
	if err != nil {
		return 1
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return 1
	}
	fmt.Printf("%d %x\n", size, hash.Sum(nil))
	return 0
}
