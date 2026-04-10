package main

import (
	"context"
	"net"
	"runtime/debug"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

// acceptMultiple accepts connections in a loop and spawns an isolated
// goroutine for each one. Handler errors are logged but do not cancel
// other connections or the accept loop itself. The loop exits when the
// context is cancelled.
func acceptMultiple(ctx context.Context, ln net.Listener, handler func(context.Context, net.Conn) error) error {
	var connCount int64
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		log.Debugf("accept loop: waiting for connection (have %d active)", atomic.LoadInt64(&connCount))
		conn, err := ln.Accept()
		if err != nil {
			// Check if context was cancelled (clean shutdown)
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			log.Errorf("accept error: %s", err)
			continue
		}

		n := atomic.AddInt64(&connCount, 1)
		log.Infof("accepted connection #%d from %s", n, conn.RemoteAddr())

		go func() {
			defer func() {
				atomic.AddInt64(&connCount, -1)
				if r := recover(); r != nil {
					log.Errorf("PANIC in connection handler: %v\n%s", r, debug.Stack())
				}
			}()
			if err := handler(ctx, conn); err != nil {
				log.Errorf("connection handler error: %s", err)
			}
		}()
	}
}
