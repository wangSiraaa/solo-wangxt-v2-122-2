// Command dnszone runs the local-only authoritative DNS zone service and
// publishes zone versions atomically into PostgreSQL.
//
// Usage:
//
//	dnszone serve    --config config.json
//	dnszone publish  --config config.json --file zone.db [--note "..."]
//	dnszone restore  --config config.json --serial N [--note "..."]
//	dnszone versions --config config.json
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"localtest/dnszone/internal/config"
	"localtest/dnszone/internal/server"
	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = runServe(args)
	case "publish":
		err = runPublish(args)
	case "restore":
		err = runRestore(args)
	case "versions":
		err = runVersions(args)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dnszone - local test-domain authoritative DNS service

Commands:
  serve     run the authoritative UDP/TCP server
  publish   atomically publish a zone file as a new version
  restore   re-publish a saved version as a new, higher serial
  versions  list published zone versions

Run "<command> -h" for command flags.
`)
}

func loadConfig(path string) (*config.Config, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stdout, "dnszone ", log.LstdFlags|log.Lmicroseconds)
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()

	srv, err := server.New(ctx, cfg, st, logger)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	file := fs.String("file", "zone.db", "RFC 1035 zone master file")
	note := fs.String("note", "", "change note stored with the version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer f.Close()

	lim := zone.Limits{MinTTL: cfg.TTLMin, MaxTTL: cfg.TTLMax}
	rrs, err := zone.Parse(f, cfg.ZoneOrigin(), lim)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()

	res, err := st.Publish(ctx, rrs, *note, lim)
	if err != nil {
		return err
	}
	fmt.Printf("published serial %d (%d record changes)\n", res.Serial, len(res.Changes))
	for _, c := range res.Changes {
		fmt.Printf("  %s %s\n", c.Action, zone.CanonicalText(c.RR))
	}
	return nil
}

// runRestore re-publishes an already stored version. The saved full zone
// record is loaded and re-validated inside the store transaction, then a
// new strictly-higher serial with a fresh change log is published; the
// serving snapshot swaps atomically via the normal publish notification.
// No history row is deleted.
func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	serial := fs.Uint("serial", 0, "serial of the saved version to re-publish")
	note := fs.String("note", "", "change note stored with the new version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serial == 0 {
		return errors.New("-serial must name an existing published version (>= 1)")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()

	lim := zone.Limits{MinTTL: cfg.TTLMin, MaxTTL: cfg.TTLMax}
	if *note == "" {
		*note = fmt.Sprintf("restore: re-publish version %d after misconfigured release", *serial)
	}
	res, err := st.Restore(ctx, uint32(*serial), *note, lim)
	if err != nil {
		return err
	}
	fmt.Printf("restored content of serial %d as new serial %d (%d record changes)\n",
		*serial, res.Serial, len(res.Changes))
	for _, c := range res.Changes {
		fmt.Printf("  %s %s\n", c.Action, zone.CanonicalText(c.RR))
	}
	return nil
}

func runVersions(args []string) error {
	fs := flag.NewFlagSet("versions", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()
	vs, err := st.ListVersions(ctx, 100)
	if err != nil {
		return err
	}
	fmt.Printf("current zone: %s\n", cfg.ZoneOrigin())
	for _, v := range vs {
		lineage := ""
		if v.RestoredFrom > 0 {
			lineage = fmt.Sprintf("restored-from %d", v.RestoredFrom)
		}
		fmt.Printf("  serial %d  %s  %q  %s\n", v.Serial,
			v.PublishedAt.Format("2006-01-02 15:04:05 MST"), v.Note, lineage)
	}
	return nil
}
