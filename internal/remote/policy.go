package remote

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/controlcmd"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

func (c *Client) NetworkPolicy(ctx context.Context, name string) (managerapi.NetworkPolicy, error) {
	var entry managerapi.NetworkPolicy
	if err := layout.ValidateName(name); err != nil {
		return entry, err
	}
	err := c.do(ctx, http.MethodGet, "/v1/sandboxes/"+name+"/net-policy", nil, false, &entry)
	return entry, err
}

func (c *Client) SetNetworkPolicy(ctx context.Context, name string, request managerapi.NetworkPolicyRequest) (Operation, error) {
	if err := layout.ValidateName(name); err != nil {
		return Operation{}, err
	}
	var op Operation
	if err := c.do(ctx, http.MethodPut, "/v1/sandboxes/"+name+"/net-policy", request, true, &op); err != nil {
		return op, err
	}
	return c.waitOperation(ctx, op)
}

func (c *Client) OrganizationPolicy(ctx context.Context, name string) (managerapi.OrganizationPolicy, error) {
	var result managerapi.OrganizationPolicy
	if err := layout.ValidateName(name); err != nil {
		return result, err
	}
	err := c.do(ctx, http.MethodGet, "/v1/sandboxes/"+name+"/policy", nil, false, &result)
	return result, err
}

func (c *Client) SetOrganizationPolicy(ctx context.Context, name string, request managerapi.OrganizationPolicyRequest) (Operation, error) {
	if err := layout.ValidateName(name); err != nil {
		return Operation{}, err
	}
	var op Operation
	if err := c.do(ctx, http.MethodPut, "/v1/sandboxes/"+name+"/policy", request, true, &op); err != nil {
		return op, err
	}
	return c.waitOperation(ctx, op)
}

func (c *Client) Audit(ctx context.Context, name string) ([]string, error) {
	if err := layout.ValidateName(name); err != nil {
		return nil, err
	}
	var result managerapi.AuditTail
	err := c.do(ctx, http.MethodGet, "/v1/sandboxes/"+name+"/audit", nil, false, &result)
	return result.Lines, err
}

func readPolicyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 512<<10 {
		return nil, errors.New("policy must be a regular file of at most 512 KiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, (512<<10)+1))
	if len(data) > 512<<10 {
		return nil, errors.New("policy exceeds 512 KiB")
	}
	return data, err
}

func remotePolicy(ctx context.Context, out, errs io.Writer, target string, client *Client, verb string, argv []string) int {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	fail := func(err error) int {
		_, _ = fmt.Fprintf(errs, "gantry %s (remote %q): %v\n", verb, target, err)
		return 1
	}
	usage := func() int {
		_, _ = fmt.Fprintf(errs, "usage: gantry %s %s -remote NAME\n", verb, map[string]string{
			"net-policy": "show NAME | set NAME FILE [--allow-local-net] | default NAME",
			"policy":     "show NAME | set NAME -bundle FILE -key PUBLIC.pem -profile PROFILE [--restart] | clear NAME [--restart]",
			"audit":      "NAME",
		}[verb])
		return 2
	}
	if verb == "audit" {
		if len(argv) != 1 {
			return usage()
		}
		lines, err := client.Audit(ctx, argv[0])
		if err != nil {
			return fail(err)
		}
		for _, line := range lines {
			_, _ = fmt.Fprintln(out, line)
		}
		return 0
	}
	if len(argv) < 2 {
		return usage()
	}
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(errs)
	var allowLocal *bool
	var bundle, key, profile *string
	var restart *bool
	if verb == "net-policy" {
		allowLocal = fs.Bool("allow-local-net", false, "allow remote host local networks (organization policy still applies)")
	} else {
		bundle = fs.String("bundle", "", "signed data-only policy bundle on this client")
		key = fs.String("key", "", "trusted RSA PUBLIC key on this client")
		profile = fs.String("profile", "", "organization profile")
		restart = fs.Bool("restart", false, "stop, update, and resume a running sandbox")
	}
	args, err := parseInterleaved(fs, argv[1:])
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil || len(args) == 0 || !layout.ValidName(args[0]) {
		return usage()
	}
	name, action := args[0], argv[0]
	var op Operation
	if verb == "net-policy" {
		switch action {
		case "show":
			if len(args) != 1 || fs.NFlag() != 0 {
				return usage()
			}
			entry, err := client.NetworkPolicy(ctx, name)
			if err != nil {
				return fail(err)
			}
			controlcmd.PrintNetworkPolicyShow(out, name+"@"+target, entry)
			return 0
		case "set", "default", "clear":
			request := managerapi.NetworkPolicyRequest{Default: action != "set", AllowLocal: *allowLocal}
			if action == "set" {
				if len(args) != 2 {
					return usage()
				}
				request.Policy, err = readPolicyFile(args[1])
				if err != nil {
					return fail(err)
				}
			} else if len(args) != 1 {
				return usage()
			}
			op, err = client.SetNetworkPolicy(ctx, name, request)
		default:
			return usage()
		}
	} else {
		if len(args) != 1 {
			return usage()
		}
		switch action {
		case "show":
			if fs.NFlag() != 0 {
				return usage()
			}
			result, err := client.OrganizationPolicy(ctx, name)
			if err != nil {
				return fail(err)
			}
			if !result.Managed {
				_, _ = fmt.Fprintln(out, "unmanaged (local policy only)")
				return 0
			}
			if err := json.NewEncoder(out).Encode(result.Info); err != nil {
				return fail(err)
			}
			return 0
		case "set", "clear":
			request := managerapi.OrganizationPolicyRequest{Clear: action == "clear", Restart: *restart}
			if !request.Clear {
				request.Snapshot, err = policy.ReadConfig(*bundle, *key, *profile)
				if err != nil {
					return fail(err)
				}
				if request.Snapshot == nil {
					return usage()
				}
			} else if *bundle != "" || *key != "" || *profile != "" {
				return usage()
			}
			op, err = client.SetOrganizationPolicy(ctx, name, request)
		default:
			_, _ = fmt.Fprintf(errs, "gantry policy %s is not supported with -remote %s; author/verify bundles locally, then upload with policy set\n", action, target)
			return 2
		}
	}
	if err != nil {
		return fail(err)
	}
	_, _ = fmt.Fprintln(out, op.Progress)
	return 0
}
