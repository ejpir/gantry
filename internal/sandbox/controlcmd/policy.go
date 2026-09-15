package controlcmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// PolicyRollout performs the CLI's explicit controlled restart path.
type PolicyRollout func(name string, snapshot *policy.Config) error

// CmdPolicy manages optional organization snapshots, not host enrollment.
func CmdPolicy(argv []string) int { return CmdPolicyWithRollout(argv, nil) }

// CmdPolicyWithRollout enables --restart when the top-level sandbox package
// supplies its lifecycle adapter. Direct package callers remain stopped-only.
func CmdPolicyWithRollout(argv []string, rollout PolicyRollout) int {
	usage := func() {
		fmt.Fprintln(os.Stderr, `usage:
  gantry policy generate -out DIR [-mount PATH ...] [-ttl 30d] [-profile developer]
  gantry policy sign -data data.json -out DIR (-signing-key private.pem | -ephemeral)
  gantry policy verify -bundle bundle.tar.gz -key public.pem -profile NAME
  gantry policy check -bundle bundle.tar.gz -key public.pem -profile NAME -action ACTION -resource JSON
  gantry policy set NAME -bundle bundle.tar.gz -key public.pem -profile PROFILE [--restart]
  gantry policy clear NAME [--restart]
  gantry policy show NAME

generate/sign create source/data.json, bundle.tar.gz and public.pem in a NEW
output directory. generate is default-deny except for explicit read-only mounts;
it uses an ephemeral test key. Neither command saves a private key.
set/clear apply live when the sandbox is running; --restart explicitly requests
stop/update/resume. This is optional, host-owned policy; there is no mandatory
device enrollment. check evaluates the organization layer only; local
network/tool rules and built-in safety checks still apply.`)
	}
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" {
		usage()
		return 0
	}
	op := argv[0]
	args := argv[1:]
	name := ""
	switch op {
	case "generate":
		return cmdPolicyGenerate(args)
	case "sign":
		return cmdPolicySign(args)
	case "set", "clear", "show":
		if len(args) == 0 {
			usage()
			return 2
		}
		name, args = args[0], args[1:]
		if err := layout.ValidateName(name); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	case "verify", "check":
	default:
		usage()
		return 2
	}
	fs := flag.NewFlagSet("policy "+op, flag.ContinueOnError)
	bundlePath := fs.String("bundle", "", "signed data-only OPA bundle")
	keyPath := fs.String("key", "", "trusted RSA public key PEM")
	profile := fs.String("profile", "", "organization profile")
	action := fs.String("action", "", "authorization action (check only)")
	resource := fs.String("resource", "{}", "resource object, without credentials or MCP arguments (check only)")
	restart := fs.Bool("restart", false, "stop, update, and resume a running sandbox (set/clear only)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(os.Stderr, "gantry policy:", err); return 1 }
	restartProvided := false
	fs.Visit(func(f *flag.Flag) { restartProvided = restartProvided || f.Name == "restart" })
	if fs.NArg() != 0 || op != "check" && (*action != "" || *resource != "{}") || op != "set" && op != "clear" && restartProvided {
		usage()
		return 2
	}
	var snapshot *policy.Config
	var err error
	switch op {
	case "show":
		if fs.NFlag() != 0 {
			usage()
			return 2
		}
	case "clear":
		if *bundlePath != "" || *keyPath != "" || *profile != "" {
			usage()
			return 2
		}
	default:
		snapshot, err = policy.ReadConfig(*bundlePath, *keyPath, *profile)
		if err != nil {
			return fail(err)
		}
		if snapshot == nil {
			return fail(fmt.Errorf("bundle, key and profile are required"))
		}
	}
	if op == "set" || op == "clear" {
		if *restart {
			if rollout == nil {
				return fail(fmt.Errorf("controlled restart is unavailable from this caller"))
			}
			err = rollout(name, snapshot)
		} else {
			err = SetOrganizationPolicy(name, snapshot)
		}
		if err != nil {
			return fail(err)
		}
		if *restart {
			fmt.Printf("organization policy %s: %s (controlled restart completed when needed)\n", op, name)
		} else {
			fmt.Printf("organization policy %s: %s (active now when running; saved when stopped)\n", op, name)
		}
		return 0
	}
	if op == "show" {
		cfg, err := config.ReadSandboxConfig(layout.Dir(name))
		if err != nil {
			return fail(err)
		}
		snapshot = cfg.OrgPolicy
		if snapshot == nil {
			fmt.Println("unmanaged (local policy only)")
			return 0
		}
	}
	engine, err := policy.New(snapshot, nil)
	if err != nil {
		return fail(err)
	}
	if op == "check" {
		if len(*resource) > 8192 || *action == "" {
			return fail(fmt.Errorf("check requires an action and a resource of at most 8192 bytes"))
		}
		var input policy.Resource
		decoder := json.NewDecoder(strings.NewReader(*resource))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			return fail(err)
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return fail(fmt.Errorf("trailing resource JSON"))
		}
		decision := engine.Evaluate(context.Background(), *action, input)
		if err := json.NewEncoder(os.Stdout).Encode(decision); err != nil {
			return fail(err)
		}
		if decision.Effect != "allow" {
			return 1
		}
		return 0
	}
	if err := json.NewEncoder(os.Stdout).Encode(engine.Info()); err != nil {
		return fail(err)
	}
	return 0
}
