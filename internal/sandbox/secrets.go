package sandbox

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/secret"
)

// secretsHandshakeJSON renders the CLI-to-daemon handshake: one line of JSON
// on the daemon's stdin. It is not placed in argv, the environment, or a file.
// Sources carry refs (env names, paths, argv) only — never values — so the
// daemon resolves them at use time through its secret.Store.
func secretsHandshakeJSON(secrets map[string]secret.Value, sources []secret.NamedSource) (string, error) {
	if len(secrets) > controlproto.SecretsHandshakeMaxEntries {
		return "", fmt.Errorf("too many secrets: got %d, limit is %d", len(secrets), controlproto.SecretsHandshakeMaxEntries)
	}
	if len(sources) > controlproto.SecretsHandshakeMaxEntries {
		return "", fmt.Errorf("too many secret sources: got %d, limit is %d", len(sources), controlproto.SecretsHandshakeMaxEntries)
	}
	type wireSource struct {
		Name      string   `json:"name"`
		Kind      string   `json:"kind"`
		Ref       string   `json:"ref,omitempty"`
		Argv      []string `json:"argv,omitempty"`
		Binding   string   `json:"binding,omitempty"`
		RefreshNs int64    `json:"refreshNs"`
	}
	ws := make([]wireSource, 0, len(sources))
	for _, ns := range sources {
		ws = append(ws, wireSource{
			Name:      ns.Name,
			Kind:      string(ns.Source.Kind),
			Ref:       ns.Source.Ref,
			Argv:      ns.Source.Argv,
			Binding:   ns.Source.Binding,
			RefreshNs: int64(ns.Source.Refresh),
		})
	}
	m := make(map[string]string, len(secrets))
	rawBytes := 0
	for name, v := range secrets {
		raw := v.Raw()
		if len(name) >= controlproto.SecretsHandshakeMaxBytes-rawBytes {
			return "", fmt.Errorf("secrets handshake exceeds %d bytes", controlproto.SecretsHandshakeMaxBytes)
		}
		rawBytes += len(name)
		if len(raw) >= controlproto.SecretsHandshakeMaxBytes-rawBytes {
			return "", fmt.Errorf("secrets handshake exceeds %d bytes", controlproto.SecretsHandshakeMaxBytes)
		}
		rawBytes += len(raw)
		m[name] = raw
	}
	b, err := json.Marshal(struct {
		Secrets map[string]string `json:"secrets"`
		Sources []wireSource      `json:"sources,omitempty"`
	}{m, ws})
	if err != nil {
		return "", fmt.Errorf("encode secrets handshake: %w", err)
	}
	if len(b)+1 > controlproto.SecretsHandshakeMaxBytes {
		return "", fmt.Errorf("secrets handshake exceeds %d bytes", controlproto.SecretsHandshakeMaxBytes)
	}
	return string(b) + "\n", nil
}

// newSecretStore builds the daemon's resolution point from the launcher
// handshake: literal values (dotenv entries, dashboard sets) plus source
// specs the Store re-resolves at use time (rotation without restart).
// Source failures are logged by name — values are structurally unloggable.
func newSecretStore(values map[string]secret.Value, sources []secret.NamedSource, logf func(string, ...any)) *secret.Store {
	st := secret.NewStore(os.LookupEnv, logf)
	for name, v := range values {
		st.PutValue(name, v)
	}
	for _, ns := range sources {
		st.Put(ns.Name, ns.Source)
	}
	return st
}

// scrubbedEnv removes exactly the keys that carry injected secret values from
// an environment block. The stdin handshake already delivers those values,
// so retaining an environment copy would expose them through host process
// inspection. With no secrets the block passes through unchanged.
func scrubbedEnv(environ []string, secrets map[string]secret.Value) []string {
	if len(secrets) == 0 {
		return environ
	}
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		key, _, _ := strings.Cut(kv, "=")
		if _, isSecret := secrets[key]; isSecret {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// readSecretsHandshake reads the launcher's one-line stdin handshake. A
// terminal or empty stdin means a manually started daemon with no secrets.
// Every source is re-validated on decode: the handshake is trusted (it
// comes from the launcher's stdin), but a malformed source must fail
// closed here rather than confuse the Store later.
func readSecretsHandshake(r *os.File) (map[string]secret.Value, []secret.NamedSource, error) {
	st, err := r.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("inspect stdin: %w", err)
	}
	if st.Mode()&os.ModeCharDevice != 0 {
		return nil, nil, nil
	}
	_ = r.SetReadDeadline(time.Now().Add(controlproto.HandshakeTimeout))
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(r), controlproto.SecretsHandshakeMaxBytes)
	_ = r.SetReadDeadline(time.Time{})
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("read stdin: %w", err)
	}
	var hs struct {
		Secrets map[string]string `json:"secrets"`
		Sources []struct {
			Name      string   `json:"name"`
			Kind      string   `json:"kind"`
			Ref       string   `json:"ref,omitempty"`
			Argv      []string `json:"argv,omitempty"`
			Binding   string   `json:"binding,omitempty"`
			RefreshNs int64    `json:"refreshNs"`
		} `json:"sources,omitempty"`
	}
	if err := json.Unmarshal(line, &hs); err != nil {
		return nil, nil, fmt.Errorf("decode JSON: %w", err)
	}
	if len(hs.Secrets) > controlproto.SecretsHandshakeMaxEntries || len(hs.Sources) > controlproto.SecretsHandshakeMaxEntries {
		return nil, nil, fmt.Errorf("too many secrets: limit is %d", controlproto.SecretsHandshakeMaxEntries)
	}
	out := make(map[string]secret.Value, len(hs.Secrets))
	for name, v := range hs.Secrets {
		out[name] = secret.Value(v)
	}
	sources := make([]secret.NamedSource, 0, len(hs.Sources))
	for _, ws := range hs.Sources {
		if err := secret.ValidateName(ws.Name); err != nil {
			return nil, nil, fmt.Errorf("handshake source: %w", err)
		}
		if ws.Binding != "" {
			if err := secret.ValidateBinding(ws.Binding); err != nil {
				return nil, nil, fmt.Errorf("handshake source %s: %w", ws.Name, err)
			}
		}
		if ws.RefreshNs < 0 {
			return nil, nil, fmt.Errorf("handshake source %s: negative refresh", ws.Name)
		}
		src := secret.Source{
			Kind:    secret.SourceKind(ws.Kind),
			Ref:     ws.Ref,
			Argv:    ws.Argv,
			Binding: ws.Binding,
			Refresh: time.Duration(ws.RefreshNs),
		}
		switch src.Kind {
		case secret.SourceEnv:
			if src.Ref == "" {
				return nil, nil, fmt.Errorf("handshake source %s: empty environment reference", ws.Name)
			}
		case secret.SourceFile:
			if src.Ref == "" {
				return nil, nil, fmt.Errorf("handshake source %s: empty file reference", ws.Name)
			}
		case secret.SourceExec:
			if len(src.Argv) == 0 || src.Argv[0] == "" {
				return nil, nil, fmt.Errorf("handshake source %s: empty exec command", ws.Name)
			}
		default:
			return nil, nil, fmt.Errorf("handshake source %s: unknown kind %q", ws.Name, ws.Kind)
		}
		sources = append(sources, secret.NamedSource{Name: ws.Name, Source: src})
	}
	return out, sources, nil
}
