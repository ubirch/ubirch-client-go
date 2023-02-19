package database

import (
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestMigrateUp_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	dbConn, err := db.DB()
	require.NoError(t, err)

	// migrate database schema to the latest version
	err = migrateUp(SQLite, dbConn)
	require.NoError(t, err)
}

func TestMigrateUp_Repeat_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	dbConn, err := db.DB()
	require.NoError(t, err)

	// migrate database schema to the latest version
	err = migrateUp(SQLite, dbConn)
	require.NoError(t, err)

	// try to migrate database schema to the latest version again
	err = migrateUp(SQLite, dbConn)
	require.NoError(t, err)
}

func TestMigrate_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	dbConn, err := db.DB()
	require.NoError(t, err)

	err = migrateTo(SQLite, dbConn, 1)
	require.NoError(t, err)
}

func TestMigrateDown_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	dbConn, err := db.DB()
	require.NoError(t, err)

	// migrate up first so we can migrate down from there
	err = migrateUp(SQLite, dbConn)
	require.NoError(t, err)

	err = migrateDown(SQLite, dbConn)
	require.NoError(t, err)
}

func TestMigrate_WrongDriver_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	dbConn, err := db.DB()
	require.NoError(t, err)

	// migrate database schema to the latest version
	err = migrateUp(PostgreSQL, dbConn)
	require.Error(t, err)
}
