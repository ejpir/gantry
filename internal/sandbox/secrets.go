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
func secretsHandshakeJSON(secrets map[string]secret.Value) (string, error) {
	if len(secrets) > controlproto.SecretsHandshakeMaxEntries {
		return "", fmt.Errorf("too many secrets: got %d, limit is %d", len(secrets), controlproto.SecretsHandshakeMaxEntries)
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
	}{m})
	if err != nil {
		return "", fmt.Errorf("encode secrets handshake: %w", err)
	}
	if len(b)+1 > controlproto.SecretsHandshakeMaxBytes {
		return "", fmt.Errorf("secrets handshake exceeds %d bytes", controlproto.SecretsHandshakeMaxBytes)
	}
	return string(b) + "\n", nil
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
func readSecretsHandshake(r *os.File) (map[string]secret.Value, error) {
	st, err := r.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect stdin: %w", err)
	}
	if st.Mode()&os.ModeCharDevice != 0 {
		return nil, nil
	}
	_ = r.SetReadDeadline(time.Now().Add(controlproto.HandshakeTimeout))
	line, err := controlproto.ReadBoundedLine(bufio.NewReader(r), controlproto.SecretsHandshakeMaxBytes)
	_ = r.SetReadDeadline(time.Time{})
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	var hs struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal(line, &hs); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	if len(hs.Secrets) > controlproto.SecretsHandshakeMaxEntries {
		return nil, fmt.Errorf("too many secrets: got %d, limit is %d", len(hs.Secrets), controlproto.SecretsHandshakeMaxEntries)
	}
	out := make(map[string]secret.Value, len(hs.Secrets))
	for name, v := range hs.Secrets {
		out[name] = secret.Value(v)
	}
	return out, nil
}
