// Package store persists zone versions, the current pointer and the
// change log in PostgreSQL. Publishing a new version is a single
// transaction: concurrent readers either see the old version in full or
// the new version in full, never a mix.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

// Store wraps a connection pool for one zone.
type Store struct {
	pool   *pgxpool.Pool
	origin string
}

// New connects and ensures the schema exists.
func New(ctx context.Context, url, origin string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	s := &Store{pool: pool, origin: dns.Fqdn(strings.ToLower(origin))}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS zone_meta (
    id              integer PRIMARY KEY DEFAULT 1,
    origin          text NOT NULL,
    current_serial  bigint NOT NULL DEFAULT 0,
    CONSTRAINT singleton CHECK (id = 1)
)`,
		`CREATE TABLE IF NOT EXISTS zone_versions (
    serial        bigint PRIMARY KEY,
    origin        text NOT NULL,
    published_at  timestamptz NOT NULL DEFAULT now(),
    note          text NOT NULL DEFAULT '',
    kind          text NOT NULL DEFAULT 'publish',
    source_serial bigint REFERENCES zone_versions(serial),
    CONSTRAINT zone_versions_kind_check CHECK (kind IN ('publish','republish'))
)`,
		`CREATE TABLE IF NOT EXISTS zone_records (
    serial    bigint NOT NULL REFERENCES zone_versions(serial) ON DELETE CASCADE,
    position  integer NOT NULL,
    rr_text   text NOT NULL,
    PRIMARY KEY (serial, position)
)`,
		`CREATE TABLE IF NOT EXISTS zone_changes (
    id          bigserial PRIMARY KEY,
    serial      bigint NOT NULL REFERENCES zone_versions(serial) ON DELETE CASCADE,
    position    integer NOT NULL,
    action      text NOT NULL CHECK (action IN ('ADD','DEL')),
    rr_text     text NOT NULL
)`,
		`CREATE INDEX IF NOT EXISTS zone_changes_serial_idx ON zone_changes(serial, position)`,
		`ALTER TABLE zone_versions ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'publish'`,
		`ALTER TABLE zone_versions ADD COLUMN IF NOT EXISTS source_serial bigint`,
		`DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'zone_versions_kind_check'
    ) THEN
        ALTER TABLE zone_versions
            ADD CONSTRAINT zone_versions_kind_check
            CHECK (kind IN ('publish','republish'));
    END IF;
END;
$$`,
		`DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'zone_versions_source_serial_fkey'
    ) THEN
        ALTER TABLE zone_versions
            ADD CONSTRAINT zone_versions_source_serial_fkey
            FOREIGN KEY (source_serial) REFERENCES zone_versions(serial);
    END IF;
END;
$$`,
		`INSERT INTO zone_meta (id, origin, current_serial)
VALUES (1, $1, 0)
ON CONFLICT (id) DO NOTHING`,
	}
	for i, stmt := range stmts {
		var err error
		if i == len(stmts)-1 {
			_, err = s.pool.Exec(ctx, stmt, s.origin)
		} else {
			_, err = s.pool.Exec(ctx, stmt)
		}
		if err != nil {
			return fmt.Errorf("migration statement %d: %w", i+1, err)
		}
	}
	return nil
}

// CurrentSerial returns the latest published serial (0 if none).
func (s *Store) CurrentSerial(ctx context.Context) (uint32, error) {
	var v int64
	err := s.pool.QueryRow(ctx,
		`SELECT current_serial FROM zone_meta WHERE id = 1`).Scan(&v)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

// PublishedVersion is one row of the version history.
type PublishedVersion struct {
	Serial       uint32
	PublishedAt  time.Time
	Note         string
	Kind         string
	SourceSerial *uint32
}

// ListVersions returns version metadata, newest first.
func (s *Store) ListVersions(ctx context.Context, limit int) ([]PublishedVersion, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT serial, published_at, note, kind, source_serial
		   FROM zone_versions ORDER BY serial DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublishedVersion
	for rows.Next() {
		var v PublishedVersion
		var serial, sourceSerial *int64
		if err := rows.Scan(&serial, &v.PublishedAt, &v.Note, &v.Kind, &sourceSerial); err != nil {
			return nil, err
		}
		if serial == nil {
			return nil, errors.New("database returned a null zone version serial")
		}
		v.Serial = uint32(*serial)
		if sourceSerial != nil {
			source := uint32(*sourceSerial)
			v.SourceSerial = &source
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// LoadSnapshot reconstructs an immutable snapshot for the given serial.
func (s *Store) LoadSnapshot(ctx context.Context, serial uint32) (*zone.Snapshot, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT rr_text FROM zone_records WHERE serial = $1 ORDER BY position`, int64(serial))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rrs, err := scanRRs(rows)
	if err != nil {
		return nil, err
	}
	if len(rrs) == 0 {
		return nil, fmt.Errorf("version %d not found", serial)
	}
	return zone.NewSnapshot(s.origin, serial, rrs)
}

// LoadCurrent returns the snapshot currently marked published, or
// (nil, nil) when no version has ever been published.
func (s *Store) LoadCurrent(ctx context.Context) (*zone.Snapshot, error) {
	serial, err := s.CurrentSerial(ctx)
	if err != nil {
		return nil, err
	}
	if serial == 0 {
		return nil, nil
	}
	return s.LoadSnapshot(ctx, serial)
}

// PublishResult reports the outcome of a publish.
type PublishResult struct {
	Serial  uint32
	Changes []zone.Change
}

// Publish validates and atomically publishes rrs as a new version.
//
// The operation is one transaction that locks the singleton meta row
// (SELECT ... FOR UPDATE): publishers serialize on that lock, the next
// serial is allocated, the full RR set and changelog are inserted and the
// current pointer is moved, all before commit. Concurrent readers can
// only observe the state before or after, never a mix.
func (s *Store) Publish(ctx context.Context, rrs []dns.RR, note string, lim zone.Limits) (*PublishResult, error) {
	return s.publishWithRetry(ctx, publishInput{
		rrs:  rrs,
		note: note,
		kind: "publish",
		lim:  lim,
	})
}

// Republish loads the complete RR set for sourceSerial, revalidates it
// against lim and the current zone rules, and publishes that content as
// the next serial. The source version and the currently served version
// both remain in history; only the current pointer advances. A missing
// source or validation failure returns before the service pointer can
// change.
func (s *Store) Republish(ctx context.Context, sourceSerial uint32, note string, lim zone.Limits) (*PublishResult, error) {
	source := int64(sourceSerial)
	return s.publishWithRetry(ctx, publishInput{
		note:         note,
		kind:         "republish",
		sourceSerial: &source,
		lim:          lim,
	})
}

type publishInput struct {
	rrs          []dns.RR
	note         string
	kind         string
	sourceSerial *int64
	lim          zone.Limits
}

func (s *Store) publishWithRetry(ctx context.Context, in publishInput) (*PublishResult, error) {
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*5) * time.Millisecond):
			}
		}
		res, err := s.publishOnce(ctx, in)
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
	return nil, fmt.Errorf("publish gave up after serialization retries: %w", lastErr)
}

func (s *Store) publishOnce(ctx context.Context, in publishInput) (*PublishResult, error) {
	// Read Committed + SELECT ... FOR UPDATE on the singleton meta row:
	// publishers queue on the row lock, and each one re-reads the current
	// serial once it acquires the lock. The full RR set, changelog and
	// pointer move commit together; readers using plain snapshot queries
	// see only the old or the new version.
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

	checked := in.rrs
	if in.sourceSerial != nil {
		var sourceExists bool
		if err := tx.QueryRow(ctx,
			`SELECT true FROM zone_versions WHERE serial = $1 FOR SHARE`,
			*in.sourceSerial).Scan(&sourceExists); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("%w: %d", ErrNoVersion, *in.sourceSerial)
			}
			return nil, err
		}
		rows, err := tx.Query(ctx,
			`SELECT rr_text FROM zone_records WHERE serial = $1 ORDER BY position FOR SHARE`,
			*in.sourceSerial)
		if err != nil {
			return nil, err
		}
		checked, err = scanRRs(rows)
		rows.Close()
		if err != nil {
			return nil, err
		}
		if len(checked) == 0 {
			return nil, fmt.Errorf("%w: %d", ErrNoVersion, *in.sourceSerial)
		}
	}

	// Re-validate against the configured TTL bounds and current zone
	// semantics before allocating/inserting a version. Historical data is
	// therefore never allowed to bypass rules that have changed since it
	// was published.
	if err := zone.Validate(checked, s.origin, in.lim); err != nil {
		return nil, err
	}

	nextSerial := prevSerial + 1
	if _, err := tx.Exec(ctx,
		`INSERT INTO zone_versions (serial, origin, note, kind, source_serial)
		 VALUES ($1, $2, $3, $4, $5)`,
		nextSerial, s.origin, in.note, in.kind, in.sourceSerial); err != nil {
		return nil, err
	}

	// Serial is rewritten onto the SOA by NewSnapshot; build the snapshot
	// for diffing/canonical storage.
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

	// Best-effort wake-up for LISTEN-ing servers; never fails a publish.
	s.notify(ctx, nextSerial)

	return &PublishResult{Serial: uint32(nextSerial), Changes: changes}, nil
}

// LoadChanges returns the stored changelog for a version (IXFR deltas).
func (s *Store) LoadChanges(ctx context.Context, serial uint32) ([]zone.Change, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT action, rr_text FROM zone_changes WHERE serial = $1 ORDER BY position`, int64(serial))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []zone.Change
	for rows.Next() {
		var action, text string
		if err := rows.Scan(&action, &text); err != nil {
			return nil, err
		}
		rr, err := dns.NewRR(text)
		if err != nil {
			return nil, fmt.Errorf("stored record %q corrupt: %w", text, err)
		}
		out = append(out, zone.Change{Action: action, RR: rr})
	}
	return out, rows.Err()
}

// ErrNoVersion is returned when the requested version does not exist.
var ErrNoVersion = errors.New("zone version not found")

// VersionExists reports whether serial is a published version.
func (s *Store) VersionExists(ctx context.Context, serial uint32) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM zone_versions WHERE serial=$1)`, int64(serial)).Scan(&exists)
	return exists, err
}

type rowScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func scanRRs(rows rowScanner) ([]dns.RR, error) {
	var rrs []dns.RR
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, err
		}
		rr, err := dns.NewRR(text)
		if err != nil {
			return nil, fmt.Errorf("stored record %q corrupt: %w", text, err)
		}
		rrs = append(rrs, rr)
	}
	return rrs, rows.Err()
}
