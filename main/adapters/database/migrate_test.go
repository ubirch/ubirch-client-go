package database

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestMigrateUp_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	db, err := sql.Open(PostgreSQL, c.DbDSN)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	// migrate database schema to the latest version
	err = migrateUp(db, PostgreSQL)
	require.NoError(t, err)
}

func TestMigrateUp_Repeat_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	db, err := sql.Open(PostgreSQL, c.DbDSN)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	// migrate database schema to the latest version
	err = migrateUp(db, PostgreSQL)
	require.NoError(t, err)

	// try to migrate database schema to the latest version again
	err = migrateUp(db, PostgreSQL)
	require.NoError(t, err)
}

func TestMigrate_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	db, err := sql.Open(PostgreSQL, c.DbDSN)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = migrateTo(db, PostgreSQL, 1)
	require.NoError(t, err)
}

func TestMigrate_Down_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	db, err := sql.Open(PostgreSQL, c.DbDSN)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = migrateDown(db, PostgreSQL)
	require.NoError(t, err)
}

func TestMigrateUp_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	db, err := sql.Open(SQLite, dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	// migrate database schema to the latest version
	err = migrateUp(db, SQLite)
	require.NoError(t, err)
}

func TestMigrateUp_Repeat_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	db, err := sql.Open(SQLite, dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	// migrate database schema to the latest version
	err = migrateUp(db, SQLite)
	require.NoError(t, err)

	// try to migrate database schema to the latest version again
	err = migrateUp(db, SQLite)
	require.NoError(t, err)
}

func TestMigrate_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	db, err := sql.Open(SQLite, dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = migrateTo(db, SQLite, 1)
	require.NoError(t, err)
}

func TestMigrate_Down_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	db, err := sql.Open(SQLite, dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	// migrate up first so we can migrate down from there
	err = migrateUp(db, SQLite)
	require.NoError(t, err)

	err = migrateDown(db, SQLite)
	require.NoError(t, err)
}

func TestMigrate_WrongDriver_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	db, err := sql.Open(PostgreSQL, c.DbDSN)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = migrateUp(db, SQLite)
	require.Error(t, err)
}

func TestMigrate_WrongDriver_Sqlite(t *testing.T) {
	var dsn = filepath.Join(t.TempDir(), testSQLiteDSN+sqliteConfig)

	db, err := sql.Open(SQLite, dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	// migrate database schema to the latest version
	err = migrateUp(db, PostgreSQL)
	require.Error(t, err)
}
