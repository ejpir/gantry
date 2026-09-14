package main

import "testing"

func TestRemoteSelectorOnLocalOnlyCommandRequiresExplicitLocal(t *testing.T) {
	t.Setenv("GANTRY_REMOTE", "unused-default")
	for _, args := range [][]string{{"--help", "-remote="}, {"-remote=", "--help"}} {
		if status := runMain(args); status != 0 {
			t.Fatalf("explicit local %v status=%d", args, status)
		}
	}
	for _, args := range [][]string{
		{"--help", "-remote=remote-host"}, {"-remote=remote-host", "--help"},
		{"--help", "-remote"}, {"--help", "-remote=", "--remote=other"},
	} {
		if status := runMain(args); status != 2 {
			t.Fatalf("unsafe/malformed selector %v status=%d", args, status)
		}
	}
}
