package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/stretchr/testify/require"
)

func TestMigrateUp(t *testing.T) {
	var dsn = os.Getenv("UBIRCH_TEST_DB_DSN")

	dbConn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	defer func() {
		err := dbConn.Close(context.Background())
		if err != nil {
			t.Error(err)
		}
	}()

	// migrate database schema to the latest version
	err = MigrateUp(dbConn)
	require.NoError(t, err)
}

func TestMigrate(t *testing.T) {
	var dsn = os.Getenv("UBIRCH_TEST_DB_DSN")

	dbConn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	defer func() {
		err := dbConn.Close(context.Background())
		if err != nil {
			t.Error(err)
		}
	}()

	err = Migrate(dbConn, 1)
	require.NoError(t, err)
}

func TestMigrate_Down(t *testing.T) {
	var dsn = os.Getenv("UBIRCH_TEST_DB_DSN")

	dbConn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	defer func() {
		err := dbConn.Close(context.Background())
		if err != nil {
			t.Error(err)
		}
	}()

	err = MigrateDown(dbConn)
	require.NoError(t, err)
}
