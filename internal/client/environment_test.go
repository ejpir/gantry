package client

import (
	"reflect"
	"testing"

	"github.com/ejpir/gantry/internal/image"
)

func TestProcessEnvironmentOverridesImageWithoutDuplicates(t *testing.T) {
	imageConfig := &image.Config{Env: []string{
		"PATH=/image/bin",
		"HTTP_PROXY=http://old.invalid:8080",
		"NO_PROXY=old.invalid",
	}}
	got := processEnvironment(imageConfig,
		[]string{"TOKEN=secret", "HTTP_PROXY=http://secret.invalid:8080"},
		[]string{"HTTP_PROXY=http://proxy.example:3128", "NO_PROXY=localhost"},
	)
	want := []string{
		"PATH=/image/bin",
		"HOME=/root",
		"TERM=xterm",
		"TOKEN=secret",
		"HTTP_PROXY=http://proxy.example:3128",
		"NO_PROXY=localhost",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment = %#v, want %#v", got, want)
	}
}

func TestConfigJSONIncludesEnvironmentOverrides(t *testing.T) {
	config, err := configJSONWithTransportCwdEnv(nil, nil, false, []string{"true"},
		&image.Config{Env: []string{"HTTPS_PROXY=http://old.invalid"}}, false, "",
		[]string{"HTTPS_PROXY=http://proxy.example:3128", "https_proxy=http://proxy.example:3128"})
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeRuntimeConfig(t, config)
	want := map[string]string{
		"HTTPS_PROXY": "http://proxy.example:3128",
		"https_proxy": "http://proxy.example:3128",
	}
	counts := make(map[string]int)
	for _, entry := range decoded.Process.Env {
		for name, value := range want {
			if entry == name+"="+value {
				counts[name]++
			}
		}
	}
	for name := range want {
		if counts[name] != 1 {
			t.Errorf("%s occurs %d times in %v", name, counts[name], decoded.Process.Env)
		}
	}
}
