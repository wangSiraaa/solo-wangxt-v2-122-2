package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

// Restore re-publishes the complete RR set of an already stored version as
// a brand-new, monotonically higher serial. The SOA serial can never move
// backwards, so a rollback is a forward publication whose content equals a
// historical version:
//
//   - the saved full zone record for sourceSerial is read back inside the
//     publish transaction (after taking the version-counter lock);
//   - it is re-validated against the *current* rules (record-type allow
//     list, TTL bounds, zone semantics). A historical version that no
//     longer passes validation aborts the transaction, leaving the serving
//     pointer untouched;
//   - a fresh serial, full record set and change log (diff from the current
//     version) are written, the current-version pointer moves, and the new
//     row records restored_from = sourceSerial.
//
// Nothing is deleted: the erroneously published version, the source
// version and the new republished version all remain in the audit history.
func (s *Store) Restore(ctx context.Context, sourceSerial uint32, note string, lim zone.Limits) (*PublishResult, error) {
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*5) * time.Millisecond):
			}
		}
		res, err := s.restoreOnce(ctx, int64(sourceSerial), note, lim)
		if err == nil {
			return res, nil
		}
		// 40001 = serialization_failure, 40P01 = deadlock_detected.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "40001" || pgErr.Code == "40P01") {
			lastErr = err
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("restore gave up after serialization retries: %w", lastErr)
}

func (s *Store) restoreOnce(ctx context.Context, sourceSerial int64, note string, lim zone.Limits) (*PublishResult, error) {
	// Same locking discipline as publishOnce: readers see only the state
	// before or the state after this transaction.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var prevSerial int64
	if err := tx.QueryRow(ctx,
		`SELECT current_serial FROM zone_meta WHERE id = 1 FOR UPDATE`).Scan(&prevSerial); err != nil {
		return nil, err
	}

	// Read back the saved complete zone record for the requested version.
	// FOR SHARE makes its existence stable for the duration of the
	// transaction and prevents a concurrent prune from removing it.
	srcRows, err := tx.Query(ctx,
		`SELECT rr_text FROM zone_records WHERE serial = $1 ORDER BY position FOR SHARE`, sourceSerial)
	if err != nil {
		return nil, err
	}
	sourceRRs, err := scanRRs(srcRows)
	srcRows.Close()
	if err != nil {
		return nil, err
	}
	if len(sourceRRs) == 0 {
		// Unknown version: nothing is written, the serving pointer stays.
		return nil, fmt.Errorf("%w: serial %d", ErrNoVersion, sourceSerial)
	}

	// Re-validate the historical record set under the *current* rules.
	checked := make([]dns.RR, 0, len(sourceRRs))
	for _, rr := range sourceRRs {
		if err := validateOne(rr, s.origin, lim); err != nil {
			return nil, fmt.Errorf("version %d fails current validation: %w", sourceSerial, err)
		}
		checked = append(checked, rr)
	}
	if err := validateAgainst(checked, s.origin, lim); err != nil {
		return nil, fmt.Errorf("version %d fails current validation: %w", sourceSerial, err)
	}

	var prev *zone.Snapshot
	if prevSerial > 0 {
		rows, err := tx.Query(ctx,
			`SELECT rr_text FROM zone_records WHERE serial = $1 ORDER BY position`, prevSerial)
		if err != nil {
			return nil, err
		}
		prevRRs, err := scanRRs(rows)
		rows.Close()
		if err != nil {
			return nil, err
		}
		prev, err = zone.NewSnapshot(s.origin, uint32(prevSerial), prevRRs)
		if err != nil {
			return nil, err
		}
	}

	nextSerial := prevSerial + 1
	if _, err := tx.Exec(ctx,
		`INSERT INTO zone_versions (serial, origin, note, restored_from) VALUES ($1, $2, $3, $4)`,
		nextSerial, s.origin, note, sourceSerial); err != nil {
		return nil, err
	}

	snap, err := zone.NewSnapshot(s.origin, uint32(nextSerial), checked)
	if err != nil {
		return nil, err
	}

	batch := &pgx.Batch{}
	for i, rr := range snap.RRs {
		batch.Queue(`INSERT INTO zone_records (serial, position, rr_text) VALUES ($1,$2,$3)`,
			nextSerial, i, zone.CanonicalText(rr))
	}
	changes := zone.Diff(prev, snap)
	for i, ch := range changes {
		batch.Queue(`INSERT INTO zone_changes (serial, position, action, rr_text) VALUES ($1,$2,$3,$4)`,
			nextSerial, i, ch.Action, zone.CanonicalText(ch.RR))
	}
	br := tx.SendBatch(ctx, batch)
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return nil, err
		}
	}
	br.Close()

	if _, err := tx.Exec(ctx,
		`UPDATE zone_meta SET current_serial = $1 WHERE id = 1`, nextSerial); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	s.notify(ctx, nextSerial)

	return &PublishResult{Serial: uint32(nextSerial), Changes: changes}, nil
}
