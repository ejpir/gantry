package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/guestasset"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/rwlayer"
)

const ideSidecarSuffix = "-ide"

type ideSidecarOptions struct {
	diskSizeMiB *uint
}

func ideSidecarName(primary string) (string, error) {
	name := primary + ideSidecarSuffix
	if err := layout.ValidateName(name); err != nil {
		return "", fmt.Errorf("cannot derive IDE sidecar name %q from %q: %w", name, primary, err)
	}
	return name, nil
}

// ensureIDESidecar creates the explicit, ordinary sandbox used by editor
// backends. It reads shares only from the primary's persisted sandbox.json;
// no guest-controlled value participates in host mount selection.
func ensureIDESidecar(primary string, options ideSidecarOptions) (string, int) {
	primary = strings.TrimSuffix(primary, ".gantry")
	if err := layout.ValidateName(primary); err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh --ide:", err)
		return "", 2
	}
	sidecar, err := ideSidecarName(primary)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh --ide:", err)
		return "", 1
	}
	primaryCfg, err := config.ReadSandboxConfig(layout.Dir(primary))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry ssh --ide: primary sandbox %q has no valid persisted configuration: %v\n", primary, err)
		return "", 1
	}
	if len(primaryCfg.Shares) == 0 {
		fmt.Fprintf(os.Stderr, "gantry ssh --ide: sandbox %q has no persisted shares; refusing to create a sidecar without a workspace\n", primary)
		return "", 1
	}
	if options.diskSizeMiB != nil {
		if err := config.ValidateRWLayerSize(*options.diskSizeMiB); err != nil {
			fmt.Fprintln(os.Stderr, "gantry ssh --ide:", err)
			return "", 2
		}
	}

	if existing, err := config.ReadSandboxConfig(layout.Dir(sidecar)); err == nil {
		if existing.IDESidecarFor != primary {
			fmt.Fprintf(os.Stderr, "gantry ssh --ide: sandbox %q already exists and is not the IDE sidecar for %q\n", sidecar, primary)
			return "", 1
		}
		if options.diskSizeMiB != nil {
			existingSize := existing.RWLayerSizeMiB
			if existingSize == 0 {
				existingSize = config.DefaultRWLayerSizeMiB
			}
			if existingSize != *options.diskSizeMiB {
				fmt.Fprintf(os.Stderr, "gantry ssh --ide: sidecar %q already has a %d MiB disk; delete it before recreating with -disk-size %d\n", sidecar, existingSize, *options.diskSizeMiB)
				return "", 1
			}
		}
		if _, alive := layout.PID(sidecar); !alive {
			if status := CmdResume(sidecar); status != 0 {
				return "", status
			}
		}
		return sidecar, 0
	}

	progress := func(format string, args ...any) { fmt.Fprintf(os.Stderr, "gantry ssh --ide: "+format+"\n", args...) }
	ideImage, err := guestasset.EnsureImage(guestasset.DefaultIDEImage(), progress)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh --ide: stage curated IDE image:", err)
		return "", 1
	}
	guestTools, toolsErr := guestasset.EnsureGuestTools(guestasset.DefaultGuestTools(), progress)
	if toolsErr != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh --ide: stage guest tools:", toolsErr)
		return "", 1
	}

	sidecarCfg := primaryCfg
	sidecarCfg.IDESidecarFor = primary
	sidecarCfg.Image = layout.AbsPath(ideImage)
	sidecarCfg.ImageRef, sidecarCfg.ImageDigest = "", ""
	sidecarCfg.ImageCfg = &image.Config{
		User: "gantry", UID: 1000, GID: 1000, WorkingDir: "/home/gantry",
		Env: []string{"HOME=/home/gantry", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}
	sidecarCfg.LayerSet = nil
	sidecarCfg.Shares = append([]string(nil), primaryCfg.Shares...)
	sidecarCfg.Ports = nil
	sidecarCfg.SSH = true
	sidecarCfg.GuestTools = layout.AbsPath(guestTools)
	// Custody never crosses the sandbox edge implicitly.
	sidecarCfg.SecretNames = nil
	sidecarCfg.SecretSources = nil
	sidecarCfg.OAuthCustody = nil
	sidecarCfg.MCP = false
	sidecarCfg.MCPRemotes = nil
	sidecarCfg.MCPFSRoot, sidecarCfg.MCPFSUser = "", ""
	idePolicy, err := ensureIDESidecarPolicy(sidecar, primaryCfg.NetPol)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh --ide: configure ide-servers egress group:", err)
		return "", 1
	}
	sidecarCfg.NetPol = idePolicy
	sidecarCfg.RW = true
	sidecarCfg.RWLayer = ""
	sidecarCfg.RWLayerSizeMiB = primaryCfg.RWLayerSizeMiB
	if options.diskSizeMiB != nil {
		sidecarCfg.RWLayerSizeMiB = *options.diskSizeMiB
	} else if sidecarCfg.RWLayerSizeMiB == 0 {
		sidecarCfg.RWLayerSizeMiB = config.DefaultRWLayerSizeMiB
	}
	rwPath, warnings, err := rwlayer.Default(sidecar, sidecarCfg.ImageIdentity(), sidecarCfg.RWLayerSizeMiB, progress)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry ssh --ide: create sidecar writable layer:", err)
		return "", 1
	}
	for _, warning := range warnings {
		progress("%s", warning)
	}
	sidecarCfg.RWLayer = rwPath

	if status := launchSandbox(sidecar, sidecarCfg, nil, true); status != 0 {
		return "", status
	}
	auditIDESidecarEdge(primary, sidecar, primary, "primary")
	auditIDESidecarEdge(sidecar, sidecar, primary, "sidecar")
	return sidecar, 0
}

var ideServerDomains = []string{
	"code.visualstudio.com",
	"update.code.visualstudio.com",
	"vscode.download.prss.microsoft.com",
	"*.visualstudio.com",
	"download.jetbrains.com",
	"download-cdn.jetbrains.com",
	"*.jetbrains.com",
	"github.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
}

// ensureIDESidecarPolicy creates the sidecar's named ide-servers policy
// projection. When the primary already has a policy, all of its rules are
// preserved and only the editor download DNS allowances are added.
func ensureIDESidecarPolicy(sidecar, primaryPolicy string) (string, error) {
	policy := map[string]any{
		"default":      "allow",
		"rules":        []any{},
		"allowDomains": []any{},
	}
	if primaryPolicy != "" {
		data, err := os.ReadFile(primaryPolicy)
		if err != nil {
			return "", err
		}
		if err := json.Unmarshal(data, &policy); err != nil {
			return "", err
		}
	}
	seen := make(map[string]bool)
	var domains []string
	if existing, ok := policy["allowDomains"].([]any); ok {
		for _, item := range existing {
			if domain, ok := item.(string); ok && !seen[domain] {
				seen[domain] = true
				domains = append(domains, domain)
			}
		}
	}
	for _, domain := range ideServerDomains {
		if !seen[domain] {
			domains = append(domains, domain)
		}
	}
	policy["allowDomains"] = domains
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "", err
	}
	if err := localsec.CreateManagerDir(sshInstallDir()); err != nil {
		return "", err
	}
	path := filepath.Join(sshInstallDir(), sidecar+"-ide-servers.json")
	if err := atomicfile.WriteFileDurable(path, data, 0o600); err != nil {
		return "", err
	}
	if err := localsec.SecureRegularFile(path); err != nil {
		return "", err
	}
	return path, nil
}

func auditIDESidecarEdge(name, sidecar, primary, edge string) {
	line := fmt.Sprintf("ide sidecar %s created for %s", sidecar, primary)
	if edge == "sidecar" {
		line = fmt.Sprintf("ide sidecar %s created from %s", sidecar, primary)
	}
	if _, alive := layout.PID(name); alive {
		if reply, err := controlproto.Call[struct {
			OK bool `json:"ok"`
		}](name, controlproto.Request{
			Op: "ide.audit", ID: controlproto.NewRequestID("ide-audit"), Args: []string{sidecar, primary, edge},
		}); err == nil && reply.OK {
			return
		}
	}
	appendIDESidecarAudit(layout.Dir(name), line)
}

func appendIDESidecarAudit(dir, line string) {
	line = sanitizeAuditLine(line)
	path := filepath.Join(dir, "audit.log")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(file, line)
	_ = file.Close()
}
