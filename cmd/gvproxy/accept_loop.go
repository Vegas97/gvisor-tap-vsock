package main

import (
	"context"
	"net"

	log "github.com/sirupsen/logrus"
)

// acceptMultiple accepts connections in a loop and spawns an isolated
// goroutine for each one. Handler errors are logged but do not cancel
// other connections or the accept loop itself. The loop exits when the
// context is cancelled.
func acceptMultiple(ctx context.Context, ln net.Listener, handler func(context.Context, net.Conn) error) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

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

		go func() {
			if err := handler(ctx, conn); err != nil {
				log.Errorf("connection handler error: %s", err)
			}
		}()
	}
}
