package sshpolicy

import "testing"

func TestExactLoopbackTarget(t *testing.T) {
	for _, target := range []struct {
		host string
		port uint64
	}{
		{"127.0.0.1", 1},
		{"127.0.0.1", 65535},
		{"::1", 8080},
		{"0:0:0:0:0:0:0:1", 8080},
	} {
		if !ExactLoopbackTarget(target.host, target.port) {
			t.Errorf("target %s:%d was refused", target.host, target.port)
		}
	}
	for _, target := range []struct {
		host string
		port uint64
	}{
		{"127.0.0.1", 0},
		{"127.0.0.1", 65536},
		{"127.0.0.2", 8080},
		{"127.1.2.3", 8080},
		{"::ffff:127.0.0.1", 8080},
		{"localhost", 8080},
		{"0.0.0.0", 8080},
		{"::", 8080},
	} {
		if ExactLoopbackTarget(target.host, target.port) {
			t.Errorf("target %s:%d was accepted", target.host, target.port)
		}
	}
}
