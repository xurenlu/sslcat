package tools_test

import (
	"database/sql"
	"testing"

	_ "github.com/xurenlu/sslcat/internal/database"
)

func TestSQLiteDriverAvailable(t *testing.T) {
	drivers := sql.Drivers()
	found := false
	for _, driver := range drivers {
		if driver == "sqlite3" {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("sqlite3 driver not registered, drivers=%v", drivers)
	}

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open sqlite3 in-memory database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("failed to ping sqlite3 database: %v", err)
	}
}
