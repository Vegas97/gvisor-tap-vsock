package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockListener is a fake net.Listener that hands out pre-loaded connections.
type mockListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newMockListener(conns ...net.Conn) *mockListener {
	ch := make(chan net.Conn, len(conns))
	for _, c := range conns {
		ch <- c
	}
	return &mockListener{
		conns:  ch,
		closed: make(chan struct{}),
	}
}

func (m *mockListener) Accept() (net.Conn, error) {
	select {
	case c := <-m.conns:
		return c, nil
	case <-m.closed:
		return nil, net.ErrClosed
	}
}

func (m *mockListener) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// --- BUG #1: Accept Loop Tests ---

func TestAcceptMultiple_AcceptsMultipleConnections(t *testing.T) {
	// Given 3 connections arrive at the listener
	// When acceptMultiple runs
	// Then all 3 should be handled

	s1, c1 := net.Pipe()
	s2, c2 := net.Pipe()
	s3, c3 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	defer c3.Close()

	ln := newMockListener(s1, s2, s3)

	var handled atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())

	handler := func(_ context.Context, conn net.Conn) error {
		handled.Add(1)
		// Simulate a long-lived connection that exits on context cancel
		<-ctx.Done()
		return nil
	}

	go func() {
		acceptMultiple(ctx, ln, handler)
	}()

	// Wait for all 3 to be handled
	deadline := time.After(2 * time.Second)
	for {
		if handled.Load() >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected 3 connections handled, got %d", handled.Load())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	ln.Close()

	if got := handled.Load(); got != 3 {
		t.Errorf("expected 3 connections handled, got %d", got)
	}
}

func TestAcceptMultiple_ContinuesAfterHandlerError(t *testing.T) {
	// Given conn-1's handler returns an error
	// When conn-2 arrives afterward
	// Then conn-2 should still be accepted and handled

	s1, c1 := net.Pipe()
	s2, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ln := newMockListener(s1, s2)

	var callCount atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler := func(_ context.Context, conn net.Conn) error {
		n := callCount.Add(1)
		if n == 1 {
			// First connection errors out immediately
			return errors.New("simulated VM disconnect")
		}
		// Second connection stays alive
		<-ctx.Done()
		return nil
	}

	go func() {
		acceptMultiple(ctx, ln, handler)
	}()

	// Wait for both to be called
	deadline := time.After(2 * time.Second)
	for {
		if callCount.Load() >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected 2 handler calls, got %d", callCount.Load())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	ln.Close()
}

func TestAcceptMultiple_StopsOnContextCancel(t *testing.T) {
	// Given the context is cancelled
	// Then acceptMultiple should return nil and not leak goroutines

	ln := newMockListener() // no connections queued — Accept will block

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- acceptMultiple(ctx, ln, func(_ context.Context, _ net.Conn) error {
			return nil
		})
	}()

	// Cancel context — loop should exit
	cancel()
	ln.Close() // unblock Accept

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error on context cancel, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acceptMultiple did not return after context cancellation")
	}
}

// --- BUG #2: Error Isolation Tests ---

func TestAcceptMultiple_ErrorIsolation(t *testing.T) {
	// Given conn-A and conn-B are both connected
	// When conn-A's handler returns an error
	// Then conn-B's handler should keep running
	// And the parent context should NOT be cancelled

	s1, c1 := net.Pipe()
	s2, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ln := newMockListener(s1, s2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connBRunning := make(chan struct{})
	connBStillAlive := make(chan struct{})

	var callCount atomic.Int32

	handler := func(handlerCtx context.Context, conn net.Conn) error {
		n := callCount.Add(1)
		if n == 1 {
			// conn-A: wait for conn-B to start, then error out
			<-connBRunning
			return errors.New("VM-A disconnected")
		}
		// conn-B: signal that we're running, then wait
		close(connBRunning)
		select {
		case <-time.After(500 * time.Millisecond):
			// If we survived 500ms after conn-A died, we're isolated
			close(connBStillAlive)
		case <-handlerCtx.Done():
			t.Error("conn-B context was cancelled — error leaked from conn-A!")
		}
		return nil
	}

	go func() {
		acceptMultiple(ctx, ln, handler)
	}()

	select {
	case <-connBStillAlive:
		// Success — conn-B survived conn-A's error
	case <-time.After(3 * time.Second):
		t.Fatal("conn-B did not survive — error isolation failed")
	}

	cancel()
	ln.Close()
}

func TestAcceptMultiple_AcceptErrorContinues(t *testing.T) {
	// Given the listener returns a transient error on Accept
	// Then the loop should continue and accept the next connection

	s1, c1 := net.Pipe()
	defer c1.Close()

	// Custom listener that fails once then succeeds
	acceptCount := atomic.Int32{}
	errListener := &errorThenSuccessListener{
		realConn: s1,
		count:    &acceptCount,
		closed:   make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var handled atomic.Int32

	handler := func(_ context.Context, _ net.Conn) error {
		handled.Add(1)
		<-ctx.Done()
		return nil
	}

	go func() {
		acceptMultiple(ctx, errListener, handler)
	}()

	deadline := time.After(2 * time.Second)
	for {
		if handled.Load() >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("handler was never called — accept error killed the loop")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Accept was called at least twice (once error, once success)
	if acceptCount.Load() < 2 {
		t.Errorf("expected at least 2 Accept calls, got %d", acceptCount.Load())
	}

	cancel()
	errListener.Close()
}

// errorThenSuccessListener returns an error on first Accept, then a real conn.
type errorThenSuccessListener struct {
	realConn net.Conn
	count    *atomic.Int32
	closed   chan struct{}
	once     sync.Once
}

func (e *errorThenSuccessListener) Accept() (net.Conn, error) {
	n := e.count.Add(1)
	if n == 1 {
		return nil, errors.New("transient accept error")
	}
	if n == 2 {
		return e.realConn, nil
	}
	// Block after delivering the real connection
	<-e.closed
	return nil, net.ErrClosed
}

func (e *errorThenSuccessListener) Close() error {
	e.once.Do(func() { close(e.closed) })
	return nil
}

func (e *errorThenSuccessListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
