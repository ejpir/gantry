package remote

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/gutil"
)

func (c *Client) ListImages(ctx context.Context) ([]managerapi.Image, error) {
	var list managerapi.ImageList
	err := c.do(ctx, http.MethodGet, "/v1/images", nil, false, &list)
	return list.Images, err
}

// BeginImagePull returns immediately with a resumable operation. An explicit
// key permits retrying an ambiguous submission after a connection failure.
func (c *Client) BeginImagePull(ctx context.Context, request managerapi.ImagePullRequest, key string) (Operation, error) {
	var operation Operation
	req, err := c.newRequest(ctx, http.MethodPost, "/v1/images/pull", request, true)
	if err != nil {
		return operation, err
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	err = c.doRequest(req, &operation)
	return operation, err
}

func (c *Client) DeleteImage(ctx context.Context, ref string) (Operation, error) {
	var op Operation
	if err := c.do(ctx, http.MethodPost, "/v1/images/delete", managerapi.ImageDeleteRequest{Ref: ref}, true, &op); err != nil {
		return op, err
	}
	return c.waitOperation(ctx, op)
}

func remoteImage(ctx context.Context, out, errs io.Writer, target string, client *Client, argv []string) int {
	usage := func() int {
		_, _ = fmt.Fprintln(errs, "usage: gantry image ls|rm REF|pull [-platform linux/ARCH] [-key KEY] REF|wait OPERATION -remote NAME")
		return 2
	}
	if len(argv) == 0 {
		return usage()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	fail := func(err error) int { _, _ = fmt.Fprintf(errs, "gantry image (remote %q): %v\n", target, err); return 1 }
	switch argv[0] {
	case "ls":
		if len(argv) != 1 {
			return usage()
		}
		images, err := client.ListImages(ctx)
		if err != nil {
			return fail(err)
		}
		sort.Slice(images, func(i, j int) bool { return images[i].Ref < images[j].Ref })
		_, _ = fmt.Fprintln(out, "REF\tDIGEST\tARCH\tSIZE\tCREATED")
		for _, img := range images {
			_, _ = fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\n", img.Ref, img.Digest, img.Arch, gutil.HumanSize(img.Size), img.Created)
		}
		return 0
	case "rm":
		if len(argv) != 2 {
			return usage()
		}
		if _, err := client.DeleteImage(ctx, argv[1]); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "gantry image: removed %s on %q\n", argv[1], target)
		return 0
	case "pull", "wait":
		var op Operation
		var err error
		if argv[0] == "wait" {
			if len(argv) != 2 {
				return usage()
			}
			op, err = client.GetOperation(ctx, argv[1])
		} else {
			fs := flag.NewFlagSet("image pull", flag.ContinueOnError)
			fs.SetOutput(errs)
			platform := fs.String("platform", "", "target platform; defaults to the remote host")
			key := fs.String("key", "", "idempotency key for retrying an ambiguous submission")
			args, parseErr := parseInterleaved(fs, argv[1:])
			if errors.Is(parseErr, flag.ErrHelp) {
				return 0
			}
			if parseErr != nil || len(args) != 1 {
				return usage()
			}
			op, err = client.BeginImagePull(ctx, managerapi.ImagePullRequest{Ref: args[0], Platform: *platform}, *key)
		}
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(errs, "operation %s on %q; reconnect with: gantry image wait %s -remote %s\n", op.ID, target, op.ID, target)
		last := ""
		_, err = client.WaitOperation(ctx, op, func(next Operation) {
			if next.Progress != "" && next.Progress != last {
				_, _ = fmt.Fprintln(out, next.Progress)
				last = next.Progress
			}
		})
		if err != nil {
			return fail(err)
		}
		return 0
	default:
		_, _ = fmt.Fprintf(errs, "gantry image %s is not supported with -remote %s; registry credentials and archive imports are managed on the server (gantry image login REGISTRY)\n", argv[0], target)
		return 2
	}
}

// parseInterleaved permits flags after positionals without treating anything
// after an explicit -- as flags. Used only by verbs without guest argv.
func parseInterleaved(fs *flag.FlagSet, argv []string) ([]string, error) {
	var args []string
	for len(argv) > 0 {
		if argv[0] == "--" {
			return append(args, argv[1:]...), nil
		}
		// Parse a leading positional ourselves; Parse otherwise consumes flags
		// and their values up to the next positional or --.
		if argv[0] == "-" || !strings.HasPrefix(argv[0], "-") {
			args = append(args, argv[0])
			argv = argv[1:]
			continue
		}
		// Find the end of the leading flag group using the FlagSet's own
		// value arity, preserving -- semantics even after valued flags.
		end := 0
		for end < len(argv) && len(argv[end]) > 1 && argv[end][0] == '-' && argv[end] != "--" {
			name, _, inline := strings.Cut(strings.TrimLeft(argv[end], "-"), "=")
			f := fs.Lookup(name)
			end++
			if f != nil && !inline {
				boolean, ok := f.Value.(interface{ IsBoolFlag() bool })
				if !ok || !boolean.IsBoolFlag() {
					if end < len(argv) {
						end++
					}
				}
			}
		}
		if err := fs.Parse(argv[:end]); err != nil {
			return nil, err
		}
		argv = argv[end:]
	}
	return args, nil
}
