package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/config"
)

func TestGetContextManagerDB(t *testing.T) {
	dbConf, err := getDatabaseConfig()
	require.NoError(t, err)

	conf := config.Config{
		PostgresDSN: dbConf.PostgresDSN,
		DbMaxConns:  dbConf.DbMaxConns,
	}

	ContextMngr, err := GetContextManager(conf)
	require.NoError(t, err)

	_, ok := ContextMngr.(*DatabaseManager)
	assert.True(t, ok, "unexpected ContextManager type")

	err = ContextMngr.Close()
	assert.NoError(t, err)
}

func TestGetContextManagerFile(t *testing.T) {
	conf := config.Config{}

	_, err := GetContextManager(conf)
	assert.Error(t, err)
}
