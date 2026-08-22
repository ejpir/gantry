//go:build !linux && !darwin && !windows

package networker

func workerEnv() []string { return []string{"GODEBUG=netdns=go"} }
