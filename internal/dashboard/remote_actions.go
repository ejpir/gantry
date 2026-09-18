package dashboard

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/image"
	"github.com/ejpir/gantry/internal/orgauth"
	"github.com/ejpir/gantry/internal/remote"
	"github.com/ejpir/gantry/internal/sandbox/config"
)

func (m *sandboxTUIModel) updateRemoteActionKey(key string) (tea.Cmd, bool) {
	switch key {
	case "a":
		return m.openRemoteAdd(nil, false), true
	case "L":
		return m.openOrganizationLogin(false), true
	case "enter", "o", "t", "d", "delete", "x":
		rows := m.remoteRows()
		if m.remoteCursor >= len(rows) {
			return nil, true
		}
		row := rows[m.remoteCursor]
		if row.suggestion != nil {
			if key == "enter" || key == "o" {
				return m.openRemoteAdd(row.suggestion, false), true
			}
			return m.showToast(tuiToastInfo, "Organization suggestion", "Add this remote before testing or using it. Organization inventory is not edited here."), true
		}
		switch key {
		case "enter", "o":
			return m.openCreateForm(row.target, ""), true
		case "t":
			owner, ok := m.tuiOperationState.Begin("remote test", row.target, false)
			if !ok {
				return nil, true
			}
			return tea.Batch(ownTUIOperationCmd(owner, testRemoteCmd(m.operations, row.target)), m.ensureAnimation()), true
		default:
			m.onboardingDialog(tuiRemoteRemoveDialog)
			m.onboardRemove, m.confirmRemove = row.target, false
			return nil, true
		}
	case "s", "e":
		return m.showToast(tuiToastInfo, "Remote inventory", "Manage sandbox lifecycle with gantry VERB NAME -remote PROFILE. These rows never target a local sandbox."), true
	}
	return nil, false
}

func testRemoteCmd(group *dashboardOperations, name string) tea.Cmd {
	return func() tea.Msg {
		result := tuiProcessDoneMsg{action: "remote test", name: name}
		if !group.begin() {
			result.err = context.Canceled
			return result
		}
		defer group.end()
		ctx, cancel := context.WithTimeout(group.ctx, 15*time.Second)
		defer cancel()
		profile, token, err := remote.Load(name)
		if err == nil {
			var client *remote.Client
			client, err = remote.Dial(profile, token)
			if err == nil {
				defer client.Close()
				_, err = client.Health(ctx)
			}
		}
		result.err = err
		return result
	}
}

func (m *sandboxTUIModel) manageRemoteCmd(action, name string) tea.Cmd {
	if m.onboardBusy {
		return nil
	}
	m.onboardBusy = true
	generation, group := m.onboardGeneration, m.operations
	ctx, cancel := context.WithTimeout(group.ctx, 15*time.Second)
	m.onboardCancel = cancel
	return func() tea.Msg {
		defer cancel()
		result := onboardResultMsg{generation: generation, kind: action, name: name}
		if !group.begin() {
			result.err = context.Canceled
			return result
		}
		defer group.end()
		if result.err = ctx.Err(); result.err == nil {
			result.err = remote.Remove(name)
		}
		return result
	}
}

func (m *sandboxTUIModel) submitRemoteCreate() (tea.Model, tea.Cmd) {
	name, ref := strings.TrimSpace(m.createName.Value()), strings.TrimSpace(m.createImage.Value())
	fail := func(err error, focus int) (tea.Model, tea.Cmd) {
		m.formError, m.createErrFocus = safeUIBlock(err.Error()), focus
		return m, m.focusCreate(focus)
	}
	if err := remote.ValidateSandboxName(name); err != nil {
		return fail(err, 0)
	}
	if ref == "" {
		return fail(fmt.Errorf("an OCI image reference is required for remote creation"), 1)
	}
	if _, err := image.ParseRef(ref); err != nil {
		return fail(err, 1)
	}
	if err := config.ValidateSandboxResources(uint(m.createMemory.Value), m.createCPUs.Value); err != nil {
		return fail(err, 7)
	}
	if err := config.ValidateRWLayerSize(uint(m.createDisk.Value)); err != nil {
		return fail(err, 8)
	}
	if err := config.ValidateProcessIsolation(m.createIsolation); err != nil {
		return fail(err, 9)
	}
	// Capture a concrete endpoint now. The command refuses a changed profile,
	// rather than silently routing the form's name to a newly configured host.
	profile, found, err := remote.Lookup(m.createRemote)
	if err != nil {
		return fail(err, 0)
	}
	if !found {
		return fail(fmt.Errorf("remote %q is no longer configured", m.createRemote), 0)
	}
	if m.createEndpoint != profile {
		return fail(fmt.Errorf("remote profile changed; reopen Create Sandbox and select the remote again"), 0)
	}
	rw := true
	request := managerapi.CreateSandboxRequest{Name: name, Image: ref, Runtime: m.createRuntime, RW: &rw,
		MemoryMiB: uint(m.createMemory.Value), CPUs: m.createCPUs.Value, DiskSizeMiB: uint(m.createDisk.Value),
		ProcessIsolation: m.createIsolation, SSH: m.createSSH, DevContainers: m.createDevContainers}
	organization := m.createOrganization
	owner, ok := m.tuiOperationState.Begin("remote create", name+"@"+profile.Name, false)
	if !ok {
		return m, nil
	}
	_ = m.tuiOperationState.SetProgress(owner, "Checking remote image cache")
	m.closeDialog()
	m.setPage(tuiRemotesPage)
	return m, tea.Batch(ownTUIOperationCmd(owner, runRemoteCreateCmd(m.operations, profile, organization, request)), m.ensureAnimation())
}

func runRemoteCreateCmd(group *dashboardOperations, expected remote.Profile, organization string, request managerapi.CreateSandboxRequest) tea.Cmd {
	return func() tea.Msg {
		if !group.begin() {
			return tuiProcessDoneMsg{action: "remote create", name: request.Name + "@" + expected.Name, err: context.Canceled}
		}
		stream := make(chan tuiProcessStreamEvent, 16)
		go func() {
			defer group.end()
			defer close(stream)
			ctx, cancel := context.WithTimeout(group.ctx, time.Hour)
			defer cancel()
			progress := func(line string) {
				select {
				case stream <- tuiProcessStreamEvent{progress: line}:
				default:
				}
			}
			err := createOnRemote(ctx, expected, organization, request, progress)
			done := &tuiProcessDoneMsg{action: "remote create", name: request.Name + "@" + expected.Name, err: err}
			select {
			case stream <- tuiProcessStreamEvent{done: done}:
			case <-group.ctx.Done():
			}
		}()
		return receiveTUIProcessStream(stream, tuiOperationOwner{})
	}
}

// createOnRemote has no local lifecycle dependency and never consults a
// default target. A fresh receipt/catalog check binds organization policy to
// the chosen endpoint before any manager mutation.
func createOnRemote(ctx context.Context, expected remote.Profile, organization string, request managerapi.CreateSandboxRequest, progress func(string)) error {
	profile, token, err := remote.Load(expected.Name)
	if err != nil {
		return err
	}
	if profile != expected {
		return fmt.Errorf("remote profile changed; choose the remote again")
	}
	if organization != "" {
		request.OrganizationPolicy, err = orgauth.PolicyForRemote(orgauth.SessionDir(), organization, profile)
		if err != nil {
			return err
		}
	}
	client, err := remote.Dial(profile, token)
	if err != nil {
		return err
	}
	defer client.Close()
	images, err := client.ListImages(ctx)
	if err != nil {
		return err
	}
	wanted, err := image.ParseRef(request.Image)
	if err != nil {
		return err
	}
	cached := false
	for _, img := range images {
		parsed, err := image.ParseRef(img.Ref)
		if err == nil && parsed == wanted {
			cached = true
			break
		}
	}
	if !cached {
		progress("Pulling " + request.Image + " on " + profile.Name)
		op, err := client.BeginImagePull(ctx, managerapi.ImagePullRequest{Ref: request.Image}, "")
		if err != nil {
			return err
		}
		op, err = client.WaitOperation(ctx, op, func(op remote.Operation) { progress(op.Progress) })
		if err != nil {
			if op.ID != "" {
				return fmt.Errorf("%w; reconnect with gantry image wait %s -remote %s", err, op.ID, profile.Name)
			}
			return err
		}
	}
	// A long pull can outlive a receipt. Do not boot under expired membership
	// or policy; a committed image pull may safely remain cached.
	if organization != "" {
		request.OrganizationPolicy, err = orgauth.PolicyForRemote(orgauth.SessionDir(), organization, profile)
		if err != nil {
			return err
		}
	}
	progress("Creating " + request.Name + " on " + profile.Name)
	_, err = client.CreateSandbox(ctx, request)
	return err
}
