package postgres

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
)

func TestMigrateUp(t *testing.T) {
	var dsn = os.Getenv("UBIRCH_TEST_DB_DSN")

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	// migrate database schema to the latest version
	err = MigrateUp(db)
	require.NoError(t, err)
}

func TestMigrate(t *testing.T) {
	var dsn = os.Getenv("UBIRCH_TEST_DB_DSN")

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = Migrate(db, 1)
	require.NoError(t, err)
}

func TestMigrate_Down(t *testing.T) {
	var dsn = os.Getenv("UBIRCH_TEST_DB_DSN")

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() {
		err := db.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = MigrateDown(db)
	require.NoError(t, err)
}
