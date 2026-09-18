package dashboard

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/ejpir/gantry/api/managerapi"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/orgauth"
	"github.com/ejpir/gantry/internal/orgauth/testidp"
	"github.com/ejpir/gantry/internal/remote"
	"github.com/ejpir/gantry/internal/remoteprofile"
	"github.com/ejpir/gantry/internal/sandbox/dashboardsvc"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
)

const onboardTestToken = "standalone-manager-token-0123456789"

type remoteIsolationService struct {
	dashboardapi.Service
	localCalls atomic.Int32
}

func (s *remoteIsolationService) Start(context.Context, lifecycle.StartRequest, lifecycle.Observer) (lifecycle.StartResult, error) {
	s.localCalls.Add(1)
	return lifecycle.StartResult{}, errors.New("local start forbidden")
}
func (s *remoteIsolationService) ValidateCreate(string, uint, uint, int, string) error {
	s.localCalls.Add(1)
	return errors.New("local validation forbidden")
}
func (s *remoteIsolationService) KernelChoices() []string {
	s.localCalls.Add(1)
	return []string{"/local/kernel"}
}

func onboardingModel(t *testing.T) (*sandboxTUIModel, *remoteIsolationService) {
	t.Helper()
	t.Setenv("GANTRY_HOME", filepath.Join(t.TempDir(), "sandboxes"))
	t.Setenv("GANTRY_REMOTE", "unrelated-default")
	service := &remoteIsolationService{Service: dashboardsvc.NewDashboardService()}
	model := newSandboxTUIModel(service)
	t.Cleanup(model.operations.close)
	model.width, model.height, model.loading = 100, 42, false
	return &model, service
}

func onboardingManager(t *testing.T, handler http.HandlerFunc) remote.Profile {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+onboardTestToken {
			t.Error("manager received an unexpected credential")
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/v1/health" {
			_ = json.NewEncoder(w).Encode(managerapi.Health{OK: true, Version: "test"})
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return remote.Profile{Name: "standalone", URL: server.URL, CACert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
}

func TestCreateWizardOffersLocalRemoteAndOrganization(t *testing.T) {
	m, _ := onboardingModel(t)
	m.updateKey(tea.KeyPressMsg{Code: 'n'})
	if m.dialog != tuiCreateLocationDialog {
		t.Fatal("new did not start location selection")
	}
	body := ansi.Strip(m.renderOnboardingDialog(tuiThemeFor(m.dark), 62))
	for _, label := range []string{"Local", "Remote", "Organization", "No organization required"} {
		if !strings.Contains(body, label) {
			t.Errorf("location chooser missing %q", label)
		}
	}
	m.updateKey(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.dialog != tuiCreateDialog || m.createRemote != "" || m.createOrganization != "" {
		t.Fatal("Local inherited a remote default")
	}
	m.closeDialog()
	m.openCreateWizard()
	m.updateKey(tea.KeyPressMsg{Code: 'r'})
	if m.dialog != tuiRemoteProfilesDialog {
		t.Fatal("standalone remote required org login")
	}
	m.updateKey(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.dialog != tuiRemoteAddDialog || !m.onboardCreating || m.onboardSuggestion != nil {
		t.Fatal("empty standalone picker did not offer add")
	}
	m.closeDialog()
	m.openCreateWizard()
	_, cmd := m.updateKey(tea.KeyPressMsg{Code: 'o'})
	if cmd == nil {
		t.Fatal("organization did not load receipts")
	}
	m.Update(cmd())
	if m.dialog != tuiOrganizationLoginDialog || !m.onboardCreating {
		t.Fatal("organization without receipt did not offer sign in")
	}
}

func TestStandaloneRemoteAddIsWriteOnlyAndReturnsToCreate(t *testing.T) {
	m, local := onboardingModel(t)
	profile := onboardingManager(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected manager endpoint") })
	m.openRemoteAdd(nil, true)
	m.onboardInputs[0].SetValue(profile.Name)
	m.onboardInputs[1].SetValue(profile.URL)
	m.onboardInputs[2].SetValue(onboardTestToken)
	m.onboardCA = profile.CACert
	m.focusOnboarding(2)
	if body := ansi.Strip(m.View().Content); strings.Contains(body, onboardTestToken) {
		t.Fatal("token rendered")
	}
	for focus := 0; focus <= len(m.onboardInputs); focus++ {
		m.focusOnboarding(focus)
		text, _ := m.dialogCopyValue()
		if strings.Contains(text, onboardTestToken) {
			t.Fatal("token copyable")
		}
	}
	cmd := m.submitRemoteAdd()
	if m.onboardInputs[2].Value() != "" || !m.onboardBusy {
		t.Fatal("submission kept secret in input")
	}
	result := cmd().(onboardResultMsg)
	if result.err != nil {
		t.Fatal(result.err)
	}
	if strings.Contains(fmt.Sprintf("%+v", result), onboardTestToken) {
		t.Fatal("credential in result")
	}
	m.Update(result)
	if m.dialog != tuiCreateDialog || m.createRemote != profile.Name || m.createOrganization != "" {
		t.Fatal("standalone add lost creation target")
	}
	if local.localCalls.Load() != 0 || len(m.createKernels) != 0 {
		t.Fatal("remote form consulted local kernel choices")
	}
	stored, token, err := remote.Load(profile.Name)
	if err != nil || stored != profile || token != onboardTestToken {
		t.Fatalf("registration failed: %v", err)
	}
	info, err := os.Stat(filepath.Join(filepath.Dir(os.Getenv("GANTRY_HOME")), "remotes", profile.Name+".token"))
	if err != nil {
		t.Fatalf("token file: %v", err)
	}
	// The successful remote.Load above verifies the protected Windows DACL;
	// Unix exposes the equivalent owner-only protection through mode bits.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("token permissions: %04o", info.Mode().Perm())
	}
	m.closeDialog()
	m.openRemoteProfiles()
	m.selectRemoteProfile(0)
	if m.createRemote != profile.Name || m.createOrganization != "" {
		t.Fatal("saved standalone selection required org")
	}
}

func TestRemoteDialogCancelAndCatalogCollisionSafety(t *testing.T) {
	m, _ := onboardingModel(t)
	profile := remote.Profile{Name: "team", URL: "https://unrelated.example.com"}
	if err := remote.Add(profile, onboardTestToken); err != nil {
		t.Fatal(err)
	}
	suggestion := orgauth.AvailableRemote{Organization: "example-org", ExpiresAt: time.Now().Add(time.Hour), Profile: remote.Profile{Name: "team", URL: "https://organization.example.com"}}
	m.onboardingDialog(tuiOrganizationRemotesDialog)
	m.onboardChoices = []orgauth.AvailableRemote{suggestion}
	m.selectOrganizationRemote(0)
	if m.dialog != tuiRemoteAddDialog || m.onboardInputs[1].Value() != suggestion.Profile.URL {
		t.Fatal("colliding profile silently reused")
	}
	m.onboardInputs[2].SetValue(onboardTestToken)
	old := m.onboardGeneration
	m.closeDialog()
	if len(m.onboardInputs) != 0 {
		t.Fatal("cancel retained secret inputs")
	}
	m.Update(onboardResultMsg{generation: old, kind: "add", name: "team"})
	m.Update(onboardURLMsg{generation: old, url: "https://stale.example.com/authorize"})
	if m.dialog != tuiNoDialog || m.onboardURL != "" {
		t.Fatal("stale operation reopened a canceled form")
	}
	if got, _, err := remote.Load("team"); err != nil || got != profile {
		t.Fatal("discovery overwrote existing profile")
	}
}

func TestRemoteCreationNeverCallsLocalService(t *testing.T) {
	m, local := onboardingModel(t)
	var calls []string
	var created managerapi.CreateSandboxRequest
	profile := onboardingManager(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/v1/images":
			_ = json.NewEncoder(w).Encode(managerapi.ImageList{})
		case "/v1/images/pull":
			_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "pull", Kind: "image.pull", State: "succeeded"})
		case "/v1/sandboxes":
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "create", Kind: "create", State: "succeeded"})
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
		}
	})
	if err := remote.Add(profile, onboardTestToken); err != nil {
		t.Fatal(err)
	}
	m.sandboxes = []tuiSandbox{{Name: "dev", State: tuiRunning}}
	m.openCreateForm(profile.Name, "")
	m.createName.SetValue("dev")
	m.createImage.SetValue("alpine")
	m.createSSH = true
	_, cmd := m.submitCreate()
	if m.tuiOperationState.Action() != "remote create" || m.page != tuiRemotesPage || m.tuiOperationState.Selection() != "" {
		t.Fatal("remote create selected a local row")
	}
	runCreateTestCommand(t, m, cmd)
	if local.localCalls.Load() != 0 {
		t.Fatal("remote creation used local lifecycle or validation")
	}
	if !reflect.DeepEqual(calls, []string{"/v1/images", "/v1/images/pull", "/v1/sandboxes"}) {
		t.Fatalf("remote sequence=%v", calls)
	}
	if created.Name != "dev" || !created.SSH || created.Kernel != "" || created.OrganizationPolicy != nil || created.RW == nil || !*created.RW {
		t.Fatalf("unexpected create request: %+v", created)
	}
	if len(m.sandboxes) != 1 || m.sandboxes[0].State != tuiRunning {
		t.Fatal("remote create changed local rows")
	}
}

func runCreateTestCommand(t *testing.T, m *sandboxTUIModel, cmd tea.Cmd) {
	t.Helper()
	if cmd == nil {
		t.Fatal("no command")
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		msg = batch[0]()
	}
	stream, ok := msg.(tuiProcessStreamMsg)
	if !ok {
		t.Fatalf("not a process stream: %T", msg)
	}
	for {
		if stream.event.done != nil {
			if stream.event.done.err != nil {
				t.Fatal(stream.event.done.err)
			}
			m.Update(*stream.event.done)
			return
		}
		select {
		case event, ok := <-stream.stream:
			if !ok {
				t.Fatal("closed before completion")
			}
			stream.event = event
		case <-time.After(10 * time.Second):
			t.Fatal("remote create timeout")
		}
	}
}

func TestRemoteCreateRefusesProfileChangeAndExpiredOrganization(t *testing.T) {
	m, local := onboardingModel(t)
	profile := onboardingManager(t, func(w http.ResponseWriter, r *http.Request) { t.Error("request after invalid target/receipt") })
	if err := remote.Add(profile, onboardTestToken); err != nil {
		t.Fatal(err)
	}
	m.openCreateForm(profile.Name, "")
	m.createName.SetValue("dev")
	m.createImage.SetValue("alpine")
	if err := remote.Remove(profile.Name); err != nil {
		t.Fatal(err)
	}
	changed := profile
	changed.URL = "https://different.example.com"
	if err := remote.Add(changed, onboardTestToken); err != nil {
		t.Fatal(err)
	}
	m.submitCreate()
	if m.tuiOperationState.Action() != "" || !strings.Contains(m.formError, "changed") || m.createRemote == "" {
		t.Fatal("changed profile fell through to local")
	}
	if err := createOnRemote(t.Context(), changed, "expired-org", managerapi.CreateSandboxRequest{Name: "dev", Image: "alpine"}, func(string) {}); err == nil {
		t.Fatal("missing organization receipt accepted")
	}
	if local.localCalls.Load() != 0 {
		t.Fatal("failed remote touched local service")
	}
}

func TestRemoteInventoryRejectsStaleWatchMessages(t *testing.T) {
	m, _ := onboardingModel(t)
	m.sandboxes = []tuiSandbox{{Name: "same", State: tuiRunning}}
	old := remoteSectionMsg{snapshot: remote.WatchSnapshot{Remote: "team", Sandboxes: []managerapi.Sandbox{{Name: "same"}}}, generation: 1}
	m.Update(old)
	m.Update(remoteSectionMsg{snapshot: remote.WatchSnapshot{Remote: "team"}, generation: 2, removed: true})
	m.Update(old)
	if len(m.remotes) != 0 || len(m.sandboxes) != 1 {
		t.Fatal("removed source was resurrected or local inventory changed")
	}
}

func TestTUIOrganizationLoginDiscoversAndCreatesWithSignedPolicy(t *testing.T) {
	m, _ := onboardingModel(t)
	idp, err := testidp.New()
	if err != nil {
		t.Fatal(err)
	}
	defer idp.Close()
	path, err := idp.WriteConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var received managerapi.CreateSandboxRequest
	profile := onboardingManager(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/images":
			_ = json.NewEncoder(w).Encode(managerapi.ImageList{Images: []managerapi.Image{{Ref: "alpine:latest"}}})
		case "/v1/sandboxes":
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(managerapi.Operation{ID: "create", State: "succeeded"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	catalog := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(orgauth.RemoteCatalog{Version: 1, Organization: testidp.Organization, Subject: "synthetic-user", ExpiresAt: time.Now().Add(time.Minute), Remotes: []remoteprofile.Profile{profile}})
	}))
	defer catalog.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c orgauth.Config
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	c.RemoteCatalog = &orgauth.CatalogConfig{URL: catalog.URL, Resource: catalog.URL, Scope: "gantry.catalog.read", CAFile: "catalog.pem"}
	data, _ = json.Marshal(c)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "catalog.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: catalog.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	oldBrowser := openOrganizationBrowser
	openOrganizationBrowser = idp.Visit
	t.Cleanup(func() { openOrganizationBrowser = oldBrowser })
	m.openOrganizationLogin(true)
	m.onboardInputs[0].SetValue(path)
	first := m.submitOrganizationLogin()().(onboardStreamMsg)
	urlMsg, ok := first.event.(onboardURLMsg)
	if !ok || urlMsg.browserFailed {
		t.Fatalf("browser message: %T", first.event)
	}
	m.Update(urlMsg)
	var result onboardResultMsg
	select {
	case msg := <-first.stream:
		result = msg.(onboardResultMsg)
	case <-time.After(10 * time.Second):
		t.Fatal("login timed out")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	m.Update(result)
	if m.dialog != tuiOrganizationRemotesDialog || len(m.onboardChoices) != 1 {
		t.Fatalf("discovery did not select organization flow: %s", m.formError)
	}
	m.selectOrganizationRemote(0)
	if m.dialog != tuiRemoteAddDialog || m.onboardInputs[2].Value() != "" {
		t.Fatal("org credential was reused as manager token")
	}
	m.onboardInputs[2].SetValue(onboardTestToken)
	m.Update(m.submitRemoteAdd()())
	if m.createOrganization != testidp.Organization || m.createRemote != profile.Name {
		t.Fatal("organization target was lost after registration")
	}
	m.createName.SetValue("org-dev")
	m.createImage.SetValue("alpine")
	_, cmd := m.submitCreate()
	runCreateTestCommand(t, m, cmd)
	if received.OrganizationPolicy == nil || received.OrganizationPolicy.Profile != "developer" {
		t.Fatal("organization creation did not carry signed policy")
	}
}
