package manager

import (
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/manager/operationstate"
	"github.com/ejpir/gantry/internal/sandbox/manager/runtimeowner"
)

const (
	// readHeaderTimeout bounds how long a local client may dawdle over its
	// request line and headers before the server drops it.
	readHeaderTimeout = 5 * time.Second

	managerAPIVersion          = "v1"
	managerMaxRequestBytes     = 1 << 20
	managerMaxOperations       = 1024
	managerMaxConnections      = 64
	managerMaxLifecycleOps     = 8
	managerMaxExecs            = 32
	managerMaxSubscribers      = 64
	managerEventBuffer         = 32
	managerDefaultOutputBytes  = 1 << 20
	managerMaximumOutputBytes  = 16 << 20
	managerDefaultExecTimeout  = 30 * time.Second
	managerMaximumExecTimeout  = time.Hour
	managerShutdownGracePeriod = 10 * time.Second
)

// managerService coordinates lifecycle operations and organization policy.
// Request/background admission belongs to runtime, while operationstate owns
// operation records and completion capabilities.
type managerService struct {
	lifecycle Lifecycle
	runtime   *managerRuntime

	operationState    *operationstate.Store
	lifecycleSlots    chan struct{}
	execSlots         chan struct{}
	sshSlots          chan struct{}
	sandboxLocks      [64]sync.RWMutex
	rawRunLock        sync.RWMutex
	feedMu            sync.Mutex
	feedEnrollmentDir string
	feedConfigured    bool
	feedOwner         *runtimeowner.Owner
	feedAudit         *log.Logger
	feedAppliedGen    atomic.Uint64

	// organizationPolicyMu is the manager-wide admission barrier. Lifecycle
	// operations and new exec/SSH sessions hold it for reading before taking a
	// sandbox shard; a feed generation holds it for writing while it fans out
	// and publishes the snapshot inherited by later creates.
	organizationPolicyMu sync.RWMutex
	organizationPolicy   *policy.Config
}

func newManagerService(lifecycle Lifecycle) *managerService {
	return &managerService{
		lifecycle:      lifecycle,
		runtime:        newManagerRuntime(),
		operationState: operationstate.New(managerMaxOperations, managerMaxSubscribers, managerEventBuffer),
		lifecycleSlots: make(chan struct{}, managerMaxLifecycleOps),
		execSlots:      make(chan struct{}, managerMaxExecs),
		sshSlots:       make(chan struct{}, managerMaxExecs),
	}
}

func (m *managerService) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", m.handleHealth)
	mux.HandleFunc("GET /v1/policy-feed/enrollment", m.handleFeedEnrollmentStatus)
	mux.HandleFunc("POST /v1/policy-feed/enrollment", m.handlePrepareFeedEnrollment)
	mux.HandleFunc("POST /v1/policy-feed/enrollment/install", m.handleInstallFeedEnrollment)
	mux.HandleFunc("POST /v1/policy-feed/enrollment/activate", m.handleActivateFeedEnrollment)
	mux.HandleFunc("GET /v1/openapi.yaml", m.handleOpenAPI)
	mux.HandleFunc("GET /v1/sandboxes", m.handleListSandboxes)
	mux.HandleFunc("POST /v1/sandboxes", m.handleCreateSandbox)
	mux.HandleFunc("POST /v1/run", m.handleRunVM)
	mux.HandleFunc("PATCH /v1/sandboxes/{name}", m.handleConfigureSandbox)
	mux.HandleFunc("GET /v1/sandboxes/{name}", m.handleGetSandbox)
	mux.HandleFunc("DELETE /v1/sandboxes/{name}", m.handleDeleteSandbox)
	mux.HandleFunc("POST /v1/sandboxes/{name}/start", m.handleStartSandbox)
	mux.HandleFunc("POST /v1/sandboxes/{name}/stop", m.handleStopSandbox)
	mux.HandleFunc("POST /v1/sandboxes/{name}/exec", m.handleExecSandbox)
	mux.HandleFunc("GET /v1/sandboxes/{name}/net-policy", m.handleGetNetworkPolicy)
	mux.HandleFunc("PUT /v1/sandboxes/{name}/net-policy", m.handleSetNetworkPolicy)
	mux.HandleFunc("GET /v1/sandboxes/{name}/policy", m.handleGetOrganizationPolicy)
	mux.HandleFunc("PUT /v1/sandboxes/{name}/policy", m.handleSetOrganizationPolicy)
	mux.HandleFunc("GET /v1/sandboxes/{name}/audit", m.handleAudit)
	mux.HandleFunc("GET /v1/dashboard", m.handleDashboardSnapshot)
	mux.HandleFunc("POST /v1/dashboard/actions", m.handleDashboardAction)
	mux.HandleFunc("POST /v1/dashboard/packets/{name}", m.handleDashboardPackets)
	mux.HandleFunc("GET /v1/ssh/hostkey", m.handleSSHHostKey)
	mux.HandleFunc("POST /v1/sandboxes/{name}/ssh", m.handleSSH)
	mux.HandleFunc("GET /v1/operations/{id}", m.handleGetOperation)
	mux.HandleFunc("GET /v1/events", m.handleEvents)
	mux.HandleFunc("GET /v1/images", m.handleListImages)
	mux.HandleFunc("POST /v1/images/pull", m.handlePullImage)
	mux.HandleFunc("POST /v1/images/delete", m.handleDeleteImage)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func (m *managerService) handleHealth(w http.ResponseWriter, _ *http.Request) {
	health := managerapi.Health{OK: true, Version: managerAPIVersion}
	if provider, ok := m.lifecycle.(dashboardServiceProvider); ok && provider.DashboardService() != nil {
		health.Capabilities = []string{"dashboard-control-v1"}
	}
	if m.feedEnrollmentDir != "" {
		health.Capabilities = append(health.Capabilities, "policy-feed-enroll-v1", "policy-feed-activate-v1")
	}
	writeManagerJSON(w, http.StatusOK, health)
}

func (m *managerService) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(managerapi.OpenAPI)
}
