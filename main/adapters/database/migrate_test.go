package database

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestMigrateUp_Postgres(t *testing.T) {
	var dsn = os.Getenv("UBIRCH_TEST_DB_DSN")

	db, err := sql.Open(string(postgresDriver), dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	// migrate database schema to the latest version
	err = MigrateUp(db, postgresDriver)
	require.NoError(t, err)
}

func TestMigrate_Postgres(t *testing.T) {
	var dsn = os.Getenv("UBIRCH_TEST_DB_DSN")

	db, err := sql.Open(string(postgresDriver), dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = Migrate(db, postgresDriver, 1)
	require.NoError(t, err)
}

func TestMigrate_Down_Postgres(t *testing.T) {
	var dsn = os.Getenv("UBIRCH_TEST_DB_DSN")

	db, err := sql.Open(string(postgresDriver), dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = MigrateDown(db, postgresDriver)
	require.NoError(t, err)
}

const testSQLiteDSN = "test.db"

func TestMigrateUp_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN)

	db, err := sql.Open(string(sqliteDriver), dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	// migrate database schema to the latest version
	err = MigrateUp(db, sqliteDriver)
	require.NoError(t, err)
}

func TestMigrate_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN)

	db, err := sql.Open(string(sqliteDriver), dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = Migrate(db, sqliteDriver, 1)
	require.NoError(t, err)
}

func TestMigrate_Down_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN)

	db, err := sql.Open(string(sqliteDriver), dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = MigrateUp(db, sqliteDriver)
	require.NoError(t, err)

	err = MigrateDown(db, sqliteDriver)
	require.NoError(t, err)
}
