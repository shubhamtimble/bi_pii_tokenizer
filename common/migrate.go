package common

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
)

// RunMigrations reads and executes the given SQL migration file(s).
func RunMigrations(db *sql.DB, paths ...string) error {
	for _, path := range paths {
		log.Printf("Running migration: %s", path)

		sqlBytes, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read migration file: %w", err)
		}
		sql := string(sqlBytes)

		if _, err := db.Exec(sql); err != nil {
			return fmt.Errorf("exec migration %s: %w", path, err)
		}
	}
	log.Println("✅ All migrations applied successfully.")
	return nil
}
