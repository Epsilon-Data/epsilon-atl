package store

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// Store provides PostgreSQL-backed persistence for the ATL.
type Store struct {
	db *sql.DB
}

// New opens a connection to PostgreSQL.
func New(databaseURL string) (*Store, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	return &Store{db: db}, nil
}

// EnsureSchema creates tables if they don't exist.
func (s *Store) EnsureSchema() error {
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("creating schema: %w", err)
	}
	return nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
