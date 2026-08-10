package workerproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const (
	// MaxConcurrentHandlers bounds retained handler goroutines per connection.
	MaxConcurrentHandlers = 32
)

// Handler answers one request. Panics become error responses.
//
// ErrShutdown is special: the response is written successfully before the
// control relationship closes and ServeRequests returns nil.
type Handler func(Request) (any, error)

// ErrShutdown asks the server to respond and then stop gracefully.
var ErrShutdown = errors.New("workerproto: graceful shutdown")

// ServeOptions selects operations that execute serially in wire order. The
// map is read-only for the duration of ServeRequestsWithOptions.
type ServeOptions struct {
	OrderedOps map[string]bool
}

// ServeRequests serves a bounded, concurrent control connection.
func ServeRequests(conn net.Conn, handlers map[string]Handler) error {
	return ServeRequestsWithOptions(conn, handlers, ServeOptions{})
}

// ServeRequestsWithOptions enforces increasing IDs, known operations, bounded
// concurrency, and optional per-connection ordering. On termination, queued
// handlers are canceled before invocation and responses from already-running
// handlers are discarded. Handler functions cannot be preempted, so callers
// remain responsible for releasing any long-running operation as their owning
// worker state tears down.
func ServeRequestsWithOptions(conn net.Conn, handlers map[string]Handler, options ServeOptions) error {
	server := requestServer{
		conn:       conn,
		handlers:   handlers,
		orderedOps: options.OrderedOps,
		slots:      make(chan struct{}, MaxConcurrentHandlers),
		done:       make(chan struct{}),
	}
	err := server.serve()
	server.terminate(err)
	return server.terminalError()
}

type requestServer struct {
	conn       net.Conn
	handlers   map[string]Handler
	orderedOps map[string]bool

	reader  messageReader
	writer  messageWriter
	writeMu sync.Mutex

	slots chan struct{}
	done  chan struct{}

	stopOnce sync.Once
	stopMu   sync.Mutex
	stopErr  error
	stopped  bool
}

func (server *requestServer) serve() error {
	var lastID uint64
	orderedTail := make(chan struct{})
	close(orderedTail)

	for {
		var request Request
		if err := server.reader.readMessage(server.conn, &request); err != nil {
			if stopped, terminalErr := server.terminal(); stopped {
				return terminalErr
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if request.ID == 0 || request.ID <= lastID {
			return fmt.Errorf("workerproto: request ID %d not increasing (last %d)", request.ID, lastID)
		}
		lastID = request.ID
		handler, ok := server.handlers[request.Op]
		if !ok {
			return fmt.Errorf("workerproto: unknown op %q", request.Op)
		}

		select {
		case server.slots <- struct{}{}:
		case <-server.done:
			return server.terminalError()
		}

		var orderedAfter, orderedDone chan struct{}
		if server.orderedOps[request.Op] {
			orderedAfter = orderedTail
			orderedDone = make(chan struct{})
			orderedTail = orderedDone
		}
		go server.handle(request, handler, orderedAfter, orderedDone)
	}
}

func (server *requestServer) handle(request Request, handler Handler, orderedAfter, orderedDone chan struct{}) {
	defer func() { <-server.slots }()
	if orderedDone != nil {
		defer close(orderedDone)
		select {
		case <-orderedAfter:
		case <-server.done:
			return
		}
	}
	select {
	case <-server.done:
		return
	default:
	}

	body, handlerErr := invokeHandler(handler, request)
	shutdown := errors.Is(handlerErr, ErrShutdown)
	response := responseFor(request, body, handlerErr, shutdown)
	if err := server.writeResponse(response); err != nil {
		server.terminate(fmt.Errorf("workerproto: write response for %q: %w", request.Op, err))
		return
	}
	if shutdown {
		server.terminate(nil)
	}
}

func invokeHandler(handler Handler, request Request) (body any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("handler panic: %v", recovered)
		}
	}()
	return handler(request)
}

func responseFor(request Request, body any, handlerErr error, shutdown bool) Response {
	response := Response{ID: request.ID, OK: handlerErr == nil || shutdown}
	if handlerErr != nil && !shutdown {
		response.Error = handlerErr.Error()
		return response
	}
	if body == nil {
		return response
	}
	raw, err := json.Marshal(body)
	if err != nil {
		response.OK = false
		response.Error = fmt.Sprintf("workerproto: encode response for %q: %v", request.Op, err)
		return response
	}
	response.Body = raw
	return response
}

func (server *requestServer) writeResponse(response Response) error {
	server.writeMu.Lock()
	defer server.writeMu.Unlock()
	select {
	case <-server.done:
		return server.terminalError()
	default:
	}
	return server.writer.writeMessage(server.conn, response)
}

// terminate closes the relationship exactly once. Closing conn interrupts the
// read loop; done independently cancels handlers that have not started.
func (server *requestServer) terminate(err error) {
	server.stopOnce.Do(func() {
		server.stopMu.Lock()
		server.stopErr = err
		server.stopped = true
		server.stopMu.Unlock()
		close(server.done)
		_ = server.conn.Close()
	})
}

func (server *requestServer) terminal() (bool, error) {
	server.stopMu.Lock()
	defer server.stopMu.Unlock()
	return server.stopped, server.stopErr
}

func (server *requestServer) terminalError() error {
	_, err := server.terminal()
	return err
}

// DecodeBody unmarshals a required request body for handlers.
func DecodeBody(request Request, value any) error {
	if len(request.Body) == 0 {
		return fmt.Errorf("missing request body")
	}
	return json.Unmarshal(request.Body, value)
}
