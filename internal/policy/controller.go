package policy

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

// Controller publishes one immutable Engine at a time to long-lived host-side
// enforcement points. Blocking is used while the sandbox daemon reconciles a
// new generation: requests which begin during that window fail closed instead
// of being evaluated against a mixture of generations.
type Controller struct {
	current atomic.Pointer[Engine]
	blocked atomic.Bool
}

func NewController(engine *Engine) *Controller {
	controller := &Controller{}
	controller.current.Store(engine)
	return controller
}

// Snapshot returns the immutable engine currently published by the
// controller. Callers may retain it while preparing or rolling back an update.
func (controller *Controller) Snapshot() *Engine {
	if controller == nil {
		return nil
	}
	return controller.current.Load()
}

// SetBlocked enables or disables the fail-closed update barrier.
func (controller *Controller) SetBlocked(blocked bool) {
	if controller != nil {
		controller.blocked.Store(blocked)
	}
}

// Store publishes an already verified immutable engine. Callers keep the
// controller blocked until all other enforcement points use the same policy.
func (controller *Controller) Store(engine *Engine) {
	if controller != nil {
		controller.current.Store(engine)
	}
}

func (controller *Controller) Evaluate(ctx context.Context, action string, resource Resource) Decision {
	engine := controller.Snapshot()
	if controller != nil && controller.blocked.Load() {
		decision := Decision{Effect: "deny", Reason: "policy_update", Rules: []string{}, Action: action}
		if engine != nil {
			decision.Organization = engine.organization
			decision.Revision = engine.revision
			decision.Profile = engine.profile
			if engine.audit != nil {
				engine.audit(decision)
			}
		}
		return decision
	}
	return engine.Evaluate(ctx, action, resource)
}

func (controller *Controller) Authorize(ctx context.Context, action string, resource Resource) error {
	decision := controller.Evaluate(ctx, action, resource)
	if decision.Effect == "allow" {
		return nil
	}
	return fmt.Errorf("organization policy denied %s: %s (org=%s revision=%s)", action, decision.Reason, decision.Organization, decision.Revision)
}

func (controller *Controller) ExpiresAt() time.Time {
	return controller.Snapshot().ExpiresAt()
}

func (controller *Controller) Info() SnapshotInfo {
	return controller.Snapshot().Info()
}
