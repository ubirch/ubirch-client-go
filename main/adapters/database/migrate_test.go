package database

import (
	"sync"
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateUp_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	// migrate database schema to the latest version
	err = migrateUp(PostgreSQL, c.DbDSN)
	require.NoError(t, err)
}

func TestMigrateUp_Repeat_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	// migrate database schema to the latest version
	err = migrateUp(PostgreSQL, c.DbDSN)
	require.NoError(t, err)

	// try to migrate database schema to the latest version again
	err = migrateUp(PostgreSQL, c.DbDSN)
	require.NoError(t, err)
}

func TestMigrate_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	err = migrateTo(PostgreSQL, c.DbDSN, 1)
	require.NoError(t, err)
}

func TestMigrateDown_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	err = migrateDown(PostgreSQL, c.DbDSN)
	require.NoError(t, err)
}

func TestMigrate_WrongDriver_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	err = migrateUp(SQLite, c.DbDSN)
	require.Error(t, err)
}

func TestMigrate_ConcurrencySafety_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	n := 4
	wg := sync.WaitGroup{}
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()

			err := migrateUp(PostgreSQL, c.DbDSN)
			assert.NoError(t, err)
		}()
	}

	wg.Wait()

	err = dropDB(PostgreSQL, c.DbDSN)
	assert.NoError(t, err)
}
