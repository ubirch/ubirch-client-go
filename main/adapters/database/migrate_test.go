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
	err = MigrateUp(db, postgresDriver)
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
	err = MigrateUp(db, postgresDriver)
	require.NoError(t, err)

	// try to migrate database schema to the latest version again
	err = MigrateUp(db, postgresDriver)
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

	err = Migrate(db, postgresDriver, 1)
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

	err = MigrateDown(db, postgresDriver)
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
	err = MigrateUp(db, sqliteDriver)
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
	err = MigrateUp(db, sqliteDriver)
	require.NoError(t, err)

	// try to migrate database schema to the latest version again
	err = MigrateUp(db, sqliteDriver)
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

	err = Migrate(db, sqliteDriver, 1)
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
	err = MigrateUp(db, sqliteDriver)
	require.NoError(t, err)

	err = MigrateDown(db, sqliteDriver)
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

	err = MigrateUp(db, sqliteDriver)
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
	err = MigrateUp(db, postgresDriver)
	require.Error(t, err)
}
