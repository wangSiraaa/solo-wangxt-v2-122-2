package store

import (
	"context"
	"strconv"
	"time"
)

const notifyChannel = "zone_published"

func (s *Store) notify(ctx context.Context, serial int64) {
	_, _ = s.pool.Exec(ctx, "SELECT pg_notify($1, $2)",
		notifyChannel, strconv.FormatInt(serial, 10))
}

// Subscribe listens on a dedicated connection for publish notifications.
// The returned channel emits the new serial. The goroutine stops when ctx
// is canceled; transient connection drops are re-established.
func (s *Store) Subscribe(ctx context.Context) <-chan uint32 {
	out := make(chan uint32, 1)
	go func() {
		defer close(out)
		for ctx.Err() == nil {
			if err := s.listenOnce(ctx, out); err != nil {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
		}
	}()
	return out
}

func (s *Store) listenOnce(ctx context.Context, out chan<- uint32) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	_, err = conn.Exec(ctx, "LISTEN "+notifyChannel)
	if err != nil {
		return err
	}

	// While waiting, also notify once after connecting so the caller can
	// catch up with anything published while disconnected.
	serial, err := s.CurrentSerial(ctx)
	if err != nil {
		return err
	}
	if serial != 0 {
		select {
		case out <- serial:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		v, err := strconv.ParseUint(notification.Payload, 10, 32)
		if err == nil && v > 0 {
			select {
			case out <- uint32(v):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
