package database

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestSQLiteDriverPersistence exercises the driver selected by sqlite_cgo.go or
// sqlite_pure.go against a real temporary database, including transaction rollback
// and data persisted across connections.
func TestSQLiteDriverPersistence(t *testing.T) {
	var driverName string
	for _, name := range sql.Drivers() {
		if name == "sqlite3" || name == "sqlite" {
			driverName = name
			break
		}
	}
	if driverName == "" {
		t.Fatal("no SQLite driver registered")
	}

	dbPath := filepath.Join(t.TempDir(), "dependency-test.db")
	db, err := sql.Open(driverName, dbPath)
	if err != nil {
		t.Fatalf("open %s database: %v", driverName, err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close %s database: %v", driverName, err)
		}
	})

	if _, err := db.Exec(`CREATE TABLE records (
		id INTEGER PRIMARY KEY,
		payload TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create table with %s: %v", driverName, err)
	}
	const recordID = 1
	const initialPayload = "initial-value"
	if _, err := db.Exec("INSERT INTO records (id, payload) VALUES (?, ?)", recordID, initialPayload); err != nil {
		t.Fatalf("insert record with %s: %v", driverName, err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin transaction with %s: %v", driverName, err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE records SET payload = ? WHERE id = ?", "rolled-back-value", recordID); err != nil {
		t.Fatalf("update transaction with %s: %v", driverName, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("roll back transaction with %s: %v", driverName, err)
	}
	var payload string
	if err := db.QueryRow("SELECT payload FROM records WHERE id = ?", recordID).Scan(&payload); err != nil {
		t.Fatalf("read record after rollback with %s: %v", driverName, err)
	}
	if payload != initialPayload {
		t.Fatalf("rollback with %s: got %q, want %q", driverName, payload, initialPayload)
	}

	const persistedPayload = "persisted-value"
	if _, err := db.Exec(`INSERT INTO records (id, payload) VALUES (?, ?)
		ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = CURRENT_TIMESTAMP`, recordID, persistedPayload); err != nil {
		t.Fatalf("upsert record with %s: %v", driverName, err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close database before reopen with %s: %v", driverName, err)
	}
	reopenedDB, err := sql.Open(driverName, dbPath)
	if err != nil {
		t.Fatalf("reopen database with %s: %v", driverName, err)
	}
	db = reopenedDB
	if err := db.QueryRow("SELECT payload FROM records WHERE id = ?", recordID).Scan(&payload); err != nil {
		t.Fatalf("read persisted record with %s: %v", driverName, err)
	}
	if payload != persistedPayload {
		t.Fatalf("persistence with %s: got %q, want %q", driverName, payload, persistedPayload)
	}

	var integrity string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil {
		t.Fatalf("check database integrity with %s: %v", driverName, err)
	}
	if integrity != "ok" {
		t.Fatalf("database integrity with %s: %s", driverName, integrity)
	}
}
