package repository

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/config"
)

func TestGetContextManagerDB(t *testing.T) {
	conf := &config.Config{
		DbDriver: SQLite,
		DbDSN:    filepath.Join(t.TempDir(), testSQLiteDSN),
	}

	ContextMngr, err := GetContextManager(conf)
	require.NoError(t, err)

	_, ok := ContextMngr.(*DatabaseManager)
	assert.True(t, ok, "unexpected ContextManager type")

	err = ContextMngr.Close()
	assert.NoError(t, err)
}
