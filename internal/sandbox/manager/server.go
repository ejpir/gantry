package manager

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/ejpir/gantry/internal/policyfeed"
	"github.com/ejpir/gantry/internal/sandbox/manager/runtimeowner"
)

// serveManager keeps the historical single-unix-socket entry point for
// existing callers and tests.
func serveManager(socketPath string, lifecycle Lifecycle) error {
	plan, err := resolveServePlan(socketPath, nil, "", "", false, "")
	if err != nil {
		return err
	}
	return serveWithOptions(context.Background(), serveOptions{plan: plan}, lifecycle)
}

// serveOptions carries the validated plan plus injectable log destinations.
type serveOptions struct {
	plan        servePlan
	policyFeeds []*policyfeed.Config
	// localAutostart must not bypass a previously configured policy feed.
	localAutostart bool
	// audit receives authentication, mutation, and policy-feed records;
	// nil defaults to stderr.
	audit *log.Logger
}

type managerTransportSecurity struct {
	tls  *serveTLS
	auth *tokenAuth
}

// serveWithOptions prepares each ownership tier in dependency order, then
// delegates reverse shutdown to runtimeowner.Owner.
func serveWithOptions(ctx context.Context, options serveOptions, lifecycle Lifecycle) error {
	if len(options.policyFeeds) > 1 {
		return fmt.Errorf("only one organization-wide policy feed may be configured")
	}
	audit := options.audit
	if audit == nil {
		audit = log.New(os.Stderr, "gantry serve: audit: ", log.LstdFlags)
	}
	service := newManagerService(lifecycle)
	owner := runtimeowner.New(runtimeowner.Hooks{
		StopAdmission:  service.stopAdmission,
		JoinRequests:   service.joinRequests,
		JoinBackground: service.joinBackground,
	}, managerShutdownGracePeriod)
	defer func() { _ = owner.Close() }()

	security, err := loadManagerTransportSecurity(options.plan, audit)
	if err != nil {
		return err
	}
	stateDir, err := prepareManagerState(options.plan, owner)
	if err != nil {
		return err
	}
	if options.localAutostart {
		if err := allowAutomaticManager(stateDir); err != nil {
			return err
		}
	}
	if err := addManagerListeners(service, owner, options.plan, security, audit); err != nil {
		return err
	}
	if err := startManagerPolicyFeeds(ctx, service, owner, options.policyFeeds, stateDir, audit); err != nil {
		return err
	}
	if err := owner.StartServers(); err != nil {
		return err
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-owner.ServeErrors():
	}
	return errors.Join(serveErr, owner.Close())
}

func loadManagerTransportSecurity(plan servePlan, audit *log.Logger) (managerTransportSecurity, error) {
	if !plan.hasTLS() {
		return managerTransportSecurity{}, nil
	}
	tlsMaterial, err := loadServeTLS(plan)
	if err != nil {
		return managerTransportSecurity{}, err
	}
	auth, err := newTokenAuth(plan.tokenFile, audit)
	if err != nil {
		return managerTransportSecurity{}, err
	}
	return managerTransportSecurity{tls: tlsMaterial, auth: auth}, nil
}
