package sandbox

// import_docker.go — read another sandbox stack's persisted state and map
// it onto a gantry sandbox.
//
// The reference sandbox daemon keeps, per sandbox:
//
//	<root>/runtimes/<name>.json          runtime spec (image template, workspace, domains)
//	<root>/runtimes/ports/<sha256(name)>.json   published ports
//	<root>/daemon.log                    task-creation lines carrying the full
//	                                     rootfs mount chain (erofs fsmeta +
//	                                     ordered layer blobs + ext4 rwlayer)
//
// …and exposes a Docker API socket (<root>/docker.sock) for live
// container lookup. The image content itself never moves: the guest
// attaches the snapshotter's layer set natively (client.LayerSet).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gantry/internal/client"
	"gantry/internal/image"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// dockerRuntime is the subset of <root>/runtimes/<name>.json we map.
type dockerRuntime struct {
	ID   string `json:"ID"`
	Spec struct {
		WorkspaceDir string `json:"WorkspaceDir"`
		RuntimeName  string `json:"RuntimeName"`
		AgentName    string `json:"AgentName"`
		Template     string `json:"Template"`
		Services     struct {
			Domains        map[string]string `json:"Domains"`
			AllowedDomains []string          `json:"AllowedDomains"`
		} `json:"Services"`
	} `json:"Spec"`
}

// dockerSandboxesRoot locates the reference daemon's state directory.
// GANTRY_DOCKER_SBX_ROOT overrides; the default is the macOS app-support
// layout.
func dockerSandboxesRoot() string {
	if v := os.Getenv("GANTRY_DOCKER_SBX_ROOT"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Library", "Application Support", "com.docker.sandboxes", "sandboxes", "sandboxd")
}

func parseDockerRuntime(b []byte) (*dockerRuntime, error) {
	var rt dockerRuntime
	if err := json.Unmarshal(b, &rt); err != nil {
		return nil, err
	}
	if rt.Spec.RuntimeName == "" {
		return nil, fmt.Errorf("runtime file has no Spec.RuntimeName")
	}
	return &rt, nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// dockerPortForward is one entry of <root>/runtimes/ports/<hash>.json.
type dockerPortForward struct {
	HostIP      string `json:"host_ip"`
	HostPort    int    `json:"host_port"`
	SandboxPort int    `json:"sandbox_port"`
	Protocol    string `json:"protocol"`
}

// parseDockerPorts renders gantry publish specs (IP:HOST:GUEST[/proto]).
func parseDockerPorts(b []byte) ([]string, error) {
	var fwds []dockerPortForward
	if err := json.Unmarshal(b, &fwds); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(fwds))
	for _, f := range fwds {
		if f.HostPort <= 0 || f.SandboxPort <= 0 {
			continue
		}
		proto := strings.ToLower(f.Protocol)
		spec := fmt.Sprintf("%d:%d", f.HostPort, f.SandboxPort)
		if f.HostIP != "" && f.HostIP != "0.0.0.0" && f.HostIP != "::" {
			spec = f.HostIP + ":" + spec
		}
		if proto == "udp" {
			spec += "/udp"
		}
		out = append(out, spec)
	}
	return out, nil
}

// --- daemon.log task-rootfs parsing -------------------------------------

var (
	// rootfs="<Go-quoted string>" inside the JSON-decoded msg field.
	rootfsValueRe = regexp.MustCompile(`rootfs=("(?:\\.|[^"\\])*")`)
	// After unquoting: mount entries of `type:"x" source:"y" options:"z"`.
	mountTokenRe = regexp.MustCompile(`(type|source|options):"([^"]*)"`)
)

// parseTaskRootfs scans daemon.log lines (newest last) for the most recent
// "creating container task" line naming containerID and extracts the
// rootfs mount chain: the ext4 rwlayer and the multi-device erofs set
// (fsmeta source + ordered device= blobs).
func parseTaskRootfs(logText string, containerID string) (ls *client.LayerSet, rwlayer string, err error) {
	idNeedle := "id=" + containerID + " "
	var spec string
	for _, line := range strings.Split(logText, "\n") {
		if !strings.Contains(line, "creating container task") || !strings.Contains(line, idNeedle) {
			continue
		}
		// The log line is JSON; decode to get the msg field.
		var entry struct {
			Msg string `json:"msg"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		m := rootfsValueRe.FindStringSubmatch(entry.Msg)
		if m == nil {
			continue
		}
		unq, uerr := strconv.Unquote(m[1])
		if uerr != nil {
			continue
		}
		spec = unq // keep scanning: the LAST hit is the most recent boot
	}
	if spec == "" {
		return nil, "", fmt.Errorf("no rootfs mount chain for container %.12s in daemon.log (start the sandbox once so the line is fresh, or pass --log)", containerID)
	}

	type mount struct {
		typ, src string
		opts     []string
	}
	var mounts []mount
	for _, tok := range mountTokenRe.FindAllStringSubmatch(spec, -1) {
		switch tok[1] {
		case "type":
			mounts = append(mounts, mount{typ: tok[2]})
		case "source":
			if len(mounts) > 0 {
				mounts[len(mounts)-1].src = tok[2]
			}
		case "options":
			if len(mounts) > 0 {
				mounts[len(mounts)-1].opts = append(mounts[len(mounts)-1].opts, tok[2])
			}
		}
	}

	ls = &client.LayerSet{}
	for _, mt := range mounts {
		switch mt.typ {
		case "ext4":
			for _, o := range mt.opts {
				if o == "rw" && mt.src != "" {
					rwlayer = mt.src
				}
			}
		case "erofs":
			if mt.src != "" {
				ls.FSMeta = mt.src
			}
			for _, o := range mt.opts {
				if strings.HasPrefix(o, "device=") {
					ls.Layers = append(ls.Layers, strings.TrimPrefix(o, "device="))
				}
			}
		}
	}
	if rwlayer == "" {
		return nil, "", fmt.Errorf("rootfs chain has no writable ext4 mount")
	}
	if ls.FSMeta == "" || len(ls.Layers) == 0 {
		return nil, "", fmt.Errorf("rootfs chain has no multi-device erofs lower (fsmeta + layers)")
	}
	return ls, rwlayer, nil
}

// --- Docker API over the daemon's unix socket ----------------------------

func dockerAPIClient(sockPath string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
	}
}

type dockerContainerSummary struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	Labels map[string]string `json:"Labels"`
}

// dockerFindContainer resolves a sandbox name to its container ID via the
// reference daemon's Docker API.
func dockerFindContainer(sockPath, name string) (*dockerContainerSummary, error) {
	resp, err := dockerAPIClient(sockPath).Get("http://d/containers/json?all=true")
	if err != nil {
		return nil, fmt.Errorf("docker API at %s: %w", sockPath, err)
	}
	defer resp.Body.Close()
	var list []dockerContainerSummary
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	for i, c := range list {
		for _, n := range c.Names {
			if strings.TrimPrefix(n, "/") == name {
				return &list[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no container named %q in the reference daemon", name)
}

// dockerImageConfig reads the container's OCI-ish config (env/entrypoint/
// cmd/user/workdir) so gantry sessions behave like the original sandbox's.
func dockerImageConfig(sockPath, containerID string) (*image.Config, error) {
	resp, err := dockerAPIClient(sockPath).Get("http://d/containers/" + containerID + "/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var ins struct {
		Config struct {
			Env        []string `json:"Env"`
			Entrypoint []string `json:"Entrypoint"`
			Cmd        []string `json:"Cmd"`
			User       string   `json:"User"`
			WorkingDir string   `json:"WorkingDir"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ins); err != nil {
		return nil, err
	}
	c := ins.Config
	if len(c.Env) == 0 && len(c.Entrypoint) == 0 && len(c.Cmd) == 0 && c.User == "" && c.WorkingDir == "" {
		return nil, nil
	}
	return &image.Config{
		Env:        c.Env,
		Entrypoint: c.Entrypoint,
		Cmd:        c.Cmd,
		User:       c.User,
		WorkingDir: c.WorkingDir,
	}, nil
}

// importedNetpol renders an egress policy mirroring the source sandbox's
// service domains. The reference stack defaults to permissive egress with
// credential injection on specific domains; gantry has no injection proxy,
// so the domains become the observed allowlist over an allow default.
func importedNetpol(rt *dockerRuntime) ([]byte, error) {
	domains := map[string]bool{}
	for d := range rt.Spec.Services.Domains {
		domains[d] = true
	}
	for _, d := range rt.Spec.Services.AllowedDomains {
		domains[d] = true
	}
	if len(domains) == 0 {
		return nil, nil
	}
	list := make([]string, 0, len(domains))
	for d := range domains {
		list = append(list, d)
	}
	sort.Strings(list)
	return json.MarshalIndent(map[string]any{
		"default":      "allow",
		"allowDomains": list,
	}, "", "  ")
}
