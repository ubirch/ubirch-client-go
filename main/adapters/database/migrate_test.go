package database

import (
	"database/sql"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestMigrateUp_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	db, err := gorm.Open(postgres.Open(c.DbDSN), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	require.NoError(t, err)

	dbConn, err := db.DB()
	require.NoError(t, err)

	// migrate database schema to the latest version
	err = migrateUp(PostgreSQL, dbConn)
	require.NoError(t, err)
}

func TestMigrateUp_Repeat_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	db, err := gorm.Open(postgres.Open(c.DbDSN), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	require.NoError(t, err)

	dbConn, err := db.DB()
	require.NoError(t, err)

	// migrate database schema to the latest version
	err = migrateUp(PostgreSQL, dbConn)
	require.NoError(t, err)

	// try to migrate database schema to the latest version again
	err = migrateUp(PostgreSQL, dbConn)
	require.NoError(t, err)
}

func TestMigrate_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	db, err := gorm.Open(postgres.Open(c.DbDSN), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	require.NoError(t, err)

	dbConn, err := db.DB()
	require.NoError(t, err)

	err = migrateTo(PostgreSQL, dbConn, 1)
	require.NoError(t, err)
}

func TestMigrateDown_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	db, err := gorm.Open(postgres.Open(c.DbDSN), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	require.NoError(t, err)

	dbConn, err := db.DB()
	require.NoError(t, err)

	err = migrateDown(PostgreSQL, dbConn)
	require.NoError(t, err)
}

func TestMigrate_WrongDriver_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	db, err := gorm.Open(postgres.Open(c.DbDSN), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	require.NoError(t, err)

	dbConn, err := db.DB()
	require.NoError(t, err)

	err = migrateUp(SQLite, dbConn)
	require.Error(t, err)
}

func TestMigrate_ConcurrencySafety_Postgres(t *testing.T) {
	// this test communicates with the actual postgres database
	if testing.Short() {
		t.Skipf("skipping integration test %s in short mode", t.Name())
	}

	c, err := getConfig()
	require.NoError(t, err)

	db, err := gorm.Open(postgres.Open(c.DbDSN), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	require.NoError(t, err)

	dbConn, err := db.DB()
	require.NoError(t, err)

	n := 4
	wg := sync.WaitGroup{}
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()

			err := migrateUp(PostgreSQL, dbConn)
			assert.NoError(t, err)
		}()
	}

	wg.Wait()

	err = dropDB(PostgreSQL, dbConn)
	assert.NoError(t, err)
}

func dropDB(driver string, db *sql.DB) error {
	migrator, err := getMigrator(driver, db)
	if err != nil {
		return err
	}
	defer closeMigrator(migrator)

	return migrator.Drop()
}
