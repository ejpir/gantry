package workerproto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const defaultCallTimeout = 30 * time.Second

// Client is the supervisor's concurrent control endpoint. Request IDs follow
// wire order, and the read loop dispatches out-of-order responses by ID.
type Client struct {
	conn    net.Conn
	write   messageWriter
	writeMu sync.Mutex

	mu        sync.Mutex
	nextID    uint64
	pending   map[uint64]chan callResult
	stickyErr error

	done     chan struct{}
	doneOnce sync.Once
	Timeout  time.Duration
}

type callResult struct {
	response Response
	err      error
}

// NewClient wraps an established control connection and starts response
// dispatch. A transport or protocol failure is terminal for the relationship.
func NewClient(conn net.Conn) *Client {
	client := &Client{
		conn:    conn,
		pending: make(map[uint64]chan callResult),
		done:    make(chan struct{}),
		Timeout: defaultCallTimeout,
	}
	go client.readLoop()
	return client
}

// failAll publishes one terminal error to every outstanding and future call.
func (client *Client) failAll(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	client.doneOnce.Do(func() {
		client.mu.Lock()
		client.stickyErr = err
		pending := client.pending
		client.pending = make(map[uint64]chan callResult)
		client.mu.Unlock()

		_ = client.conn.Close()
		for _, result := range pending {
			result <- callResult{err: err}
		}
		close(client.done)
	})
}

func (client *Client) readLoop() {
	var reader messageReader
	for {
		var response Response
		if err := reader.readMessage(client.conn, &response); err != nil {
			client.failAll(err)
			return
		}

		client.mu.Lock()
		result, pending := client.pending[response.ID]
		if pending {
			delete(client.pending, response.ID)
		}
		maxIssued := client.nextID
		client.mu.Unlock()

		if pending {
			result <- callResult{response: response}
			continue
		}
		// Stale replies belong to calls abandoned by context cancellation.
		if response.ID <= maxIssued {
			continue
		}
		client.failAll(fmt.Errorf("workerproto: response ID %d never issued (max %d)", response.ID, maxIssued))
		return
	}
}

// Call issues one request using the client's configured timeout.
func (client *Client) Call(op string, body, out any) error {
	return client.CallWithTimeout(op, body, out, client.Timeout)
}

// CallWithTimeout is Call with an explicit round-trip bound. A non-positive
// timeout uses the package default.
func (client *Client) CallWithTimeout(op string, body, out any, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = defaultCallTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := client.CallContext(ctx, op, body, out); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("workerproto: call %q timed out after %s", op, timeout)
		}
		return err
	}
	return nil
}

// CallContext waits without an implicit deadline. Context cancellation
// abandons this call only; a late response is recognized and discarded.
func (client *Client) CallContext(ctx context.Context, op string, body, out any) error {
	var raw json.RawMessage
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		raw = encoded
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Assignment and write share a lock because IDs must increase in wire order
	// even when callers arrive concurrently.
	client.writeMu.Lock()
	if err := ctx.Err(); err != nil {
		client.writeMu.Unlock()
		return err
	}
	client.mu.Lock()
	if client.stickyErr != nil {
		err := client.stickyErr
		client.mu.Unlock()
		client.writeMu.Unlock()
		return err
	}
	client.nextID++
	id := client.nextID
	result := make(chan callResult, 1)
	client.pending[id] = result
	client.mu.Unlock()

	writeErr := client.write.writeMessage(client.conn, Request{ID: id, Op: op, Body: raw})
	client.writeMu.Unlock()
	if writeErr != nil {
		client.failAll(writeErr)
		return writeErr
	}

	select {
	case call := <-result:
		if call.err != nil {
			return call.err
		}
		if !call.response.OK {
			return errors.New(call.response.Error)
		}
		if out != nil && len(call.response.Body) != 0 {
			return json.Unmarshal(call.response.Body, out)
		}
		return nil
	case <-ctx.Done():
		client.mu.Lock()
		delete(client.pending, id)
		client.mu.Unlock()
		return ctx.Err()
	}
}

// Close ends the control relationship and fails outstanding calls.
func (client *Client) Close() error {
	err := client.conn.Close()
	client.failAll(net.ErrClosed)
	return err
}
