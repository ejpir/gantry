package manager

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/localsec"
	"github.com/ejpir/gantry/internal/sandbox/manager/runtimeowner"
)

const (
	managerSocketProbeTimeout = 200 * time.Millisecond
	managerHTTPIdleTimeout    = 2 * time.Minute
	managerHTTPMaxHeaderBytes = 16 << 10
)

type openedManagerListener struct {
	listener     net.Listener
	handler      http.Handler
	endpoint     string
	sameUserOnly bool
}

func addManagerListeners(service *managerService, owner *runtimeowner.Owner, plan servePlan, security managerTransportSecurity, audit *log.Logger) error {
	slots := make(chan struct{}, managerMaxConnections)
	for _, spec := range plan.listeners {
		opened, err := openManagerListener(service, spec, security, audit)
		if err != nil {
			return err
		}
		handler := service.ownedHandler(opened.handler)
		server := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: readHeaderTimeout,
			IdleTimeout:       managerHTTPIdleTimeout,
			MaxHeaderBytes:    managerHTTPMaxHeaderBytes,
			ErrorLog:          log.New(os.Stderr, "gantry serve: http: ", log.LstdFlags),
		}
		limited := &limitedListener{
			Listener: opened.listener, slots: slots, sameUserOnly: opened.sameUserOnly,
		}
		if err := owner.AddServer(server, limited, opened.endpoint); err != nil {
			closeUnadoptedManagerListener(opened)
			return err
		}
	}
	return nil
}

func openManagerListener(service *managerService, spec listenSpec, security managerTransportSecurity, audit *log.Logger) (openedManagerListener, error) {
	switch spec.network {
	case "unix":
		return openManagerUnixListener(service, spec)
	case "tls":
		return openManagerTLSListener(service, spec, security, audit)
	default:
		return openedManagerListener{}, fmt.Errorf("unsupported listener network %q", spec.network)
	}
}

func openManagerUnixListener(service *managerService, spec listenSpec) (openedManagerListener, error) {
	socketPath := spec.address
	if conn, err := net.DialTimeout("unix", socketPath, managerSocketProbeTimeout); err == nil {
		_ = conn.Close()
		return openedManagerListener{}, fmt.Errorf("manager is already listening on %s", socketPath)
	}
	if err := removeStaleManagerSocket(socketPath); err != nil {
		return openedManagerListener{}, err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return openedManagerListener{}, err
	}
	if err := localsec.SecureEndpoint(socketPath); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return openedManagerListener{}, fmt.Errorf("secure manager endpoint: %w", err)
	}
	fmt.Printf("gantry serve: listening on %s\n", spec)
	return openedManagerListener{
		listener: listener, handler: service.handler(), endpoint: socketPath, sameUserOnly: true,
	}, nil
}

func removeStaleManagerSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect stale socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket manager endpoint %s", socketPath)
	}
	if err := os.Remove(socketPath); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}

func openManagerTLSListener(service *managerService, spec listenSpec, security managerTransportSecurity, audit *log.Logger) (openedManagerListener, error) {
	plain, err := net.Listen("tcp", spec.address)
	if err != nil {
		return openedManagerListener{}, err
	}
	listener := tls.NewListener(plain, security.tls.config)
	fmt.Printf("gantry serve: listening on %s (tls fingerprint %s; bearer auth required)\n", spec, security.tls.fingerprint)
	return openedManagerListener{
		listener: listener,
		handler:  service.authenticatedHandler(security.auth, audit),
	}, nil
}

func closeUnadoptedManagerListener(opened openedManagerListener) {
	_ = opened.listener.Close()
	if opened.endpoint != "" {
		_ = os.Remove(opened.endpoint)
	}
}
