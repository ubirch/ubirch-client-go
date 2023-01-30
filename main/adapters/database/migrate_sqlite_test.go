package database

import (
	"path/filepath"
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestMigrateUp_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	// migrate database schema to the latest version
	err := migrateUp(SQLite, dsn)
	require.NoError(t, err)
}

func TestMigrateUp_Repeat_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	// migrate database schema to the latest version
	err := migrateUp(SQLite, dsn)
	require.NoError(t, err)

	// try to migrate database schema to the latest version again
	err = migrateUp(SQLite, dsn)
	require.NoError(t, err)
}

func TestMigrate_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	err := migrateTo(SQLite, dsn, 1)
	require.NoError(t, err)
}

func TestMigrateDown_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	// migrate up first so we can migrate down from there
	err := migrateUp(SQLite, dsn)
	require.NoError(t, err)

	err = migrateDown(SQLite, dsn)
	require.NoError(t, err)
}

func TestMigrate_WrongDriver_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	// migrate database schema to the latest version
	err := migrateUp(PostgreSQL, dsn)
	require.Error(t, err)
}
