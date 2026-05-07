package common

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
)

const migrationTrackerDDL = `
CREATE TABLE IF NOT EXISTS _migrations (
    id          SERIAL PRIMARY KEY,
    filename    TEXT NOT NULL UNIQUE,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);`

// RunMigrations applies SQL migration files exactly once each by tracking
// applied filenames in the `_migrations` table.
//
// Bootstrap: on the first run after this tracker was introduced, if the
// `_migrations` table is empty but `pii_tokens` already exists in the schema,
// the runner assumes the database is on a legacy schema and **records every
// known migration as already applied without re-executing it**. Subsequent
// runs skip everything cleanly. New migrations added later are detected as
// missing from the tracker and applied as usual.
//
// Fresh installs: tracker is empty AND `pii_tokens` does not exist → every
// migration runs in order and is recorded.
func RunMigrations(db *sql.DB, paths ...string) error {
	if _, err := db.Exec(migrationTrackerDDL); err != nil {
		return fmt.Errorf("create migrations tracker: %w", err)
	}

	// Bootstrap-on-existing-DB: if the tracker is empty but pii_tokens already
	// exists, mark all known migrations as already applied so we don't try to
	// re-run them against an evolved schema.
	var trackerCount int
	if err := db.QueryRow(`SELECT count(*) FROM _migrations`).Scan(&trackerCount); err != nil {
		return fmt.Errorf("count tracker rows: %w", err)
	}
	if trackerCount == 0 {
		var hasTokens bool
		if err := db.QueryRow(
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='pii_tokens')`,
		).Scan(&hasTokens); err != nil {
			return fmt.Errorf("probe pii_tokens: %w", err)
		}
		if hasTokens {
			log.Println("Migration tracker empty but pii_tokens already exists — seeding tracker with known migrations as already applied (no SQL executed).")
			for _, path := range paths {
				name := filepath.Base(path)
				if _, err := db.Exec(
					`INSERT INTO _migrations (filename) VALUES ($1) ON CONFLICT DO NOTHING`,
					name,
				); err != nil {
					return fmt.Errorf("seed tracker for %s: %w", name, err)
				}
				log.Printf("Marked as applied (existing schema): %s", name)
			}
			log.Println("✅ Migration tracker bootstrap complete.")
			return nil
		}
	}

	// Normal path: apply each unapplied migration in order.
	applied := 0
	skipped := 0
	for _, path := range paths {
		name := filepath.Base(path)

		var alreadyApplied bool
		if err := db.QueryRow(
			`SELECT EXISTS (SELECT 1 FROM _migrations WHERE filename = $1)`,
			name,
		).Scan(&alreadyApplied); err != nil {
			return fmt.Errorf("check applied state for %s: %w", name, err)
		}
		if alreadyApplied {
			log.Printf("Skip (already applied): %s", name)
			skipped++
			continue
		}

		log.Printf("Running migration: %s", path)
		sqlBytes, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read migration file %s: %w", path, err)
		}
		if _, err := db.Exec(string(sqlBytes)); err != nil {
			return fmt.Errorf("exec migration %s: %w", path, err)
		}
		if _, err := db.Exec(
			`INSERT INTO _migrations (filename) VALUES ($1)`,
			name,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		log.Printf("Applied: %s", name)
		applied++
	}
	log.Printf("✅ Migrations done — applied %d, skipped %d.", applied, skipped)
	return nil
}
