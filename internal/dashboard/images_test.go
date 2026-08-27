package dashboard

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/sandbox/dashboardsvc"
)

func imagesTestModel() sandboxTUIModel {
	m := newSandboxTUIModel(dashboardsvc.NewDashboardService())
	m.loading = false
	m.width, m.height = 170, 34
	m.page = tuiImagesPage
	m.images = []tuiImageRow{
		{Ref: "debian:bookworm-slim", Digest: "sha256:bbb222", Arch: "amd64", Size: 2048, Created: "2025-01-02T03:04:05Z"},
		{
			Ref: "ghcr.io/org/app:latest", Digest: "sha256:aaa111", Arch: "arm64", Size: 4096,
			Created: "2025-01-02T03:04:05Z", InUse: true, User: "1000", WorkingDir: "/app",
			Entrypoint: []string{"/bin/server"}, EnvCount: 2,
		},
	}
	m.registries = []tuiRegistryRow{
		{Registry: "docker.io", Username: "(anonymous)"},
		{Registry: "ghcr.io", Username: "octocat", Source: "gantry credentials.json auths (base64)", HasSecret: true},
	}
	return m
}

func TestSandboxTUIImagesPageRenderingAndNavigation(t *testing.T) {
	m := imagesTestModel()
	m.imageCursor = 1
	plain := ansi.Strip(m.View().Content)
	for _, want := range []string{
		"9 IMAGES 2", "REF", "DIGEST", "ARCH", "SIZE", "debian:bookworm-slim",
		"ghcr.io/org/app:latest", "in use by a sandbox",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("images page missing %q:\n%s", want, plain)
		}
	}

	model, _ := m.updateKey(tea.KeyPressMsg{Code: 's'})
	m = *model.(*sandboxTUIModel)
	if m.imageSection != tuiImageSectionCredentials {
		t.Fatalf("section after s = %q", m.imageSection)
	}
	plain = ansi.Strip(m.View().Content)
	for _, want := range []string{"REGISTRY", "USERNAME", "SECRET", "ghcr.io", "octocat", "2 registries  •  1 logins"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("credentials section missing %q:\n%s", want, plain)
		}
	}

	m.page = tuiSandboxesPage
	model, _ = m.updateKey(tea.KeyPressMsg{Code: '9'})
	m = *model.(*sandboxTUIModel)
	if m.page != tuiImagesPage {
		t.Fatalf("page after 9 = %d, want images", m.page)
	}

	m.images = nil
	m.imageSection = tuiImageSectionImages
	plain = ansi.Strip(m.View().Content)
	if !strings.Contains(plain, "No cached images") {
		t.Fatalf("empty images page missing guidance:\n%s", plain)
	}
}

func TestSandboxTUIImagePullDialogAndArgv(t *testing.T) {
	m := imagesTestModel()
	model, cmd := m.updateKey(tea.KeyPressMsg{Code: 'p'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiImagePullDialog || cmd == nil {
		t.Fatalf("pull dialog = %d cmd=%v", m.dialog, cmd)
	}
	plain := ansi.Strip(m.renderImagePullDialog(tuiThemeFor(m.dark), 62))
	for _, want := range []string{"Pull Image", "Image reference", "Architecture", "auto"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("pull dialog missing %q:\n%s", want, plain)
		}
	}

	model, _ = m.submitImagePull()
	m = *model.(*sandboxTUIModel)
	if m.formError == "" || m.pullFocus != 0 || m.busyAction != "" {
		t.Fatalf("empty submit: error=%q focus=%d busy=%q", m.formError, m.pullFocus, m.busyAction)
	}

	m.pullRef.SetValue("ghcr.io/org/app:latest")
	if got := strings.Join(m.imagePullArgv(m.pullRef.Value()), " "); got != "image pull ghcr.io/org/app:latest" {
		t.Fatalf("automatic-platform argv = %q", got)
	}
	m.cycleImagePullArch(1)
	m.cycleImagePullArch(1) // auto -> amd64 -> arm64
	if m.pullArch != "arm64" {
		t.Fatalf("arch after cycling = %q", m.pullArch)
	}
	if got := strings.Join(m.imagePullArgv(m.pullRef.Value()), " "); got != "image pull -platform linux/arm64 ghcr.io/org/app:latest" {
		t.Fatalf("explicit-platform argv = %q", got)
	}

	model, cmd = m.submitImagePull()
	m = *model.(*sandboxTUIModel)
	if m.busyAction != "image pull" || m.busyName != "ghcr.io/org/app:latest" || m.dialog != tuiNoDialog || cmd == nil {
		t.Fatalf("pull submit: action=%q name=%q dialog=%d cmd=%v", m.busyAction, m.busyName, m.dialog, cmd)
	}
}

func TestSandboxTUIImageRemovePruneAndLogout(t *testing.T) {
	m := imagesTestModel()
	m.imageCursor = 1
	model, _ := m.updateKey(tea.KeyPressMsg{Code: 'd'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiImageRemoveDialog {
		t.Fatalf("remove dialog = %d", m.dialog)
	}
	plain := ansi.Strip(m.renderImageRemoveDialog(tuiThemeFor(m.dark), 54))
	if !strings.Contains(plain, "ghcr.io/org/app:latest") || !strings.Contains(plain, "currently references") {
		t.Fatalf("remove dialog lacks in-use warning:\n%s", plain)
	}
	model, cmd := m.updateKey(tea.KeyPressMsg{Code: 'y'})
	m = *model.(*sandboxTUIModel)
	if m.busyAction != "image remove" || m.busyName != "ghcr.io/org/app:latest" || m.dialog != tuiNoDialog || cmd == nil {
		t.Fatalf("remove confirmation: action=%q name=%q dialog=%d cmd=%v", m.busyAction, m.busyName, m.dialog, cmd)
	}

	m = imagesTestModel()
	model, _ = m.updateKey(tea.KeyPressMsg{Code: 'u'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiImagePruneDialog {
		t.Fatalf("prune dialog = %d", m.dialog)
	}
	plain = ansi.Strip(m.renderImagePruneDialog(tuiThemeFor(m.dark), 54))
	if !strings.Contains(plain, "1 unused image") || !strings.Contains(plain, "2.0K") {
		t.Fatalf("prune dialog lacks count/size:\n%s", plain)
	}
	model, cmd = m.updateKey(tea.KeyPressMsg{Code: 'y'})
	m = *model.(*sandboxTUIModel)
	if m.busyAction != "image prune" || m.dialog != tuiNoDialog || cmd == nil {
		t.Fatalf("prune confirmation: action=%q dialog=%d cmd=%v", m.busyAction, m.dialog, cmd)
	}

	m = imagesTestModel()
	m.images[0].InUse = true
	model, cmd = m.updateKey(tea.KeyPressMsg{Code: 'u'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiNoDialog || m.toast == nil || cmd == nil {
		t.Fatalf("nothing-to-prune result: dialog=%d toast=%v cmd=%v", m.dialog, m.toast, cmd)
	}

	m = imagesTestModel()
	m.imageSection = tuiImageSectionCredentials
	m.registryCursor = 0
	model, cmd = m.updateKey(tea.KeyPressMsg{Code: 'd'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiNoDialog || m.toast == nil || cmd == nil {
		t.Fatalf("anonymous logout result: dialog=%d toast=%v cmd=%v", m.dialog, m.toast, cmd)
	}
	m.registryCursor = 1
	model, _ = m.updateKey(tea.KeyPressMsg{Code: 'd'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiRegistryLogoutDialog {
		t.Fatalf("logout dialog = %d", m.dialog)
	}
	model, cmd = m.updateKey(tea.KeyPressMsg{Code: 'y'})
	m = *model.(*sandboxTUIModel)
	if m.busyAction != "registry logout" || m.busyName != "ghcr.io" || m.dialog != tuiNoDialog || cmd == nil {
		t.Fatalf("logout confirmation: action=%q name=%q dialog=%d cmd=%v", m.busyAction, m.busyName, m.dialog, cmd)
	}
}

func TestSandboxTUIRegistryLoginIsWriteOnly(t *testing.T) {
	m := imagesTestModel()
	m.imageSection = tuiImageSectionCredentials
	m.registryCursor = 1
	model, cmd := m.updateKey(tea.KeyPressMsg{Code: 'a'})
	m = *model.(*sandboxTUIModel)
	if m.dialog != tuiRegistryLoginDialog || cmd == nil {
		t.Fatalf("login dialog = %d cmd=%v", m.dialog, cmd)
	}
	if m.loginRegistry.Value() != "ghcr.io" || m.loginUsername.Value() != "octocat" {
		t.Fatalf("login prefill = %q / %q", m.loginRegistry.Value(), m.loginUsername.Value())
	}

	m.loginPassword.SetValue("never-render-this")
	m.focusRegistryLogin(2)
	plain := ansi.Strip(m.View().Content)
	if strings.Contains(plain, "never-render-this") || !strings.Contains(plain, "••") {
		t.Fatalf("registry password was not masked:\n%s", plain)
	}
	copied, _ := m.dialogCopyValue()
	if strings.Contains(copied, "never-render-this") {
		t.Fatalf("copy action exposed registry password: %q", copied)
	}

	m.loginPassword.Reset()
	model, _ = m.submitRegistryLogin()
	m = *model.(*sandboxTUIModel)
	if m.formError == "" || m.loginFocus != 2 {
		t.Fatalf("empty password: error=%q focus=%d", m.formError, m.loginFocus)
	}
	m.loginRegistry.SetValue("")
	m.loginPassword.SetValue("token")
	model, _ = m.submitRegistryLogin()
	m = *model.(*sandboxTUIModel)
	if m.formError == "" || m.loginFocus != 0 {
		t.Fatalf("empty registry: error=%q focus=%d", m.formError, m.loginFocus)
	}

	m.loginRegistry.SetValue("quay.io")
	m.loginUsername.SetValue("robot")
	m.loginPassword.SetValue("token")
	model, cmd = m.submitRegistryLogin()
	m = *model.(*sandboxTUIModel)
	if m.busyAction != "registry login" || m.busyName != "quay.io" || m.dialog != tuiNoDialog || cmd == nil {
		t.Fatalf("login submit: action=%q name=%q dialog=%d cmd=%v", m.busyAction, m.busyName, m.dialog, cmd)
	}
	if m.loginPassword.Value() != "" {
		t.Fatal("submitted login retained its password")
	}

	m.openRegistryLoginDialog()
	m.loginPassword.SetValue("another-token")
	m.closeDialog()
	if m.loginPassword.Value() != "" {
		t.Fatal("closing login dialog retained its password")
	}
}

type registryLoginRecordingService struct {
	dashboardapi.Service
	commandCalls int
	stored       dashboardapi.RegistryLoginRequest
}

func (s *registryLoginRecordingService) Command(argv ...string) (*exec.Cmd, error) {
	s.commandCalls++
	return nil, errors.New("registry credentials must not use argv")
}

func (s *registryLoginRecordingService) ValidateRegistryLogin(dashboardapi.RegistryLoginRequest) error {
	return nil
}

func (s *registryLoginRecordingService) StoreRegistryLogin(request dashboardapi.RegistryLoginRequest) (string, error) {
	s.stored = request
	return "plaintext fallback warning", nil
}

func runTUITestCommand(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		var messages []tea.Msg
		for _, child := range batch {
			messages = append(messages, runTUITestCommand(child)...)
		}
		return messages
	}
	return []tea.Msg{msg}
}

func TestRegistryLoginNeverUsesCommandArgv(t *testing.T) {
	service := &registryLoginRecordingService{Service: dashboardsvc.NewDashboardService()}
	m := newSandboxTUIModel(service)
	m.loading = false
	m.page = tuiImagesPage
	m.imageSection = tuiImageSectionCredentials
	m.openRegistryLoginDialog()
	m.loginRegistry.SetValue("ghcr.io")
	m.loginUsername.SetValue("octocat")
	m.loginPassword.SetValue("super-secret-token")

	model, cmd := m.submitRegistryLogin()
	m = *model.(*sandboxTUIModel)
	if service.commandCalls != 0 {
		t.Fatalf("registry login called Command %d times", service.commandCalls)
	}
	messages := runTUITestCommand(cmd)
	if service.commandCalls != 0 {
		t.Fatalf("executing registry login called Command %d times", service.commandCalls)
	}
	if service.stored.Registry != "ghcr.io" || service.stored.Username != "octocat" || service.stored.Secret.Raw() != "super-secret-token" {
		t.Fatalf("StoreRegistryLogin request = registry %q username %q secret-present %t",
			service.stored.Registry, service.stored.Username, service.stored.Secret.Raw() != "")
	}
	foundDone := false
	for _, message := range messages {
		if done, ok := message.(tuiProcessDoneMsg); ok {
			foundDone = true
			if done.action != "registry login" || strings.Contains(done.output, "super-secret-token") {
				t.Fatalf("registry completion leaked or mislabeled data: %#v", done)
			}
		}
	}
	if !foundDone || m.loginPassword.Value() != "" {
		t.Fatalf("login completion missing=%t retained-password=%t", !foundDone, m.loginPassword.Value() != "")
	}
}

func TestSandboxTUIImagesSelectionSurvivesRefresh(t *testing.T) {
	m := imagesTestModel()
	m.imageCursor = 1
	m.registryCursor = 1
	model, _ := m.handleRefresh(tuiRefreshMsg{
		images: []tuiImageRow{
			{Ref: "ghcr.io/org/app:latest", Digest: "sha256:new", Arch: "arm64", InUse: true},
			{Ref: "zzz:latest", Digest: "sha256:zzz", Arch: "arm64"},
		},
		registries: []tuiRegistryRow{{Registry: "ghcr.io", HasSecret: true}, {Registry: "quay.io"}},
		at:         time.Now(),
	})
	m = *model.(*sandboxTUIModel)
	if m.imageCursor != 0 || m.images[0].Digest != "sha256:new" {
		t.Fatalf("image selection after refresh = %d in %#v", m.imageCursor, m.images)
	}
	if m.registryCursor != 0 || m.registries[0].Registry != "ghcr.io" {
		t.Fatalf("registry selection after refresh = %d in %#v", m.registryCursor, m.registries)
	}
}

func TestImagePullProgressLines(t *testing.T) {
	if got, ok := operationProgressLine("gantry image: layer 2/4: 12MB (sha256:abc)"); !ok || got != "layer 2/4: 12MB (sha256:abc)" {
		t.Fatalf("layer progress = %q, %t", got, ok)
	}
	if _, ok := operationProgressLine("gantry image pull: denied: unauthorized"); ok {
		t.Fatal("pull failure was classified as progress")
	}
	if _, ok := operationProgressLine("gantry image: "); ok {
		t.Fatal("empty image status was classified as progress")
	}
}

func TestSanitizeSnapshotCoversImagesAndRegistries(t *testing.T) {
	snapshot := dashboardapi.Snapshot{
		Images: []dashboardapi.Image{{
			Ref: "ghcr.io/org/app\x1b[31m\nspoof", Digest: "sha256:abc\x1b[2J", Arch: "arm64\nspoof",
			Created: "2025\nspoof", User: "1000\nspoof", WorkingDir: "/app\x1b[2J",
			Entrypoint: []string{"/bin/server\nspoof"}, Cmd: []string{"--serve\x1b[31m"},
		}},
		Registries: []dashboardapi.RegistryAuth{{
			Registry: "ghcr.io\x1b[2J", Username: "octocat\nspoof", Source: "helper\x1b[31m",
		}},
	}
	sanitizeSnapshot(&snapshot)
	image := snapshot.Images[0]
	registry := snapshot.Registries[0]
	if image.Ref != "ghcr.io/org/app spoof" || image.Digest != "sha256:abc" || image.Arch != "arm64 spoof" ||
		image.Created != "2025 spoof" || image.User != "1000 spoof" || image.WorkingDir != "/app" ||
		image.Entrypoint[0] != "/bin/server spoof" || image.Cmd[0] != "--serve" {
		t.Fatalf("image was not sanitized: %#v", image)
	}
	if registry.Registry != "ghcr.io" || registry.Username != "octocat spoof" || registry.Source != "helper" {
		t.Fatalf("registry was not sanitized: %#v", registry)
	}
}
