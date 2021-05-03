package vars

const (
	PostgreSql                  string = "postgres"
	PostgreSqlPort              int    = 5432
	PostgreSqlIdentityTableName string = "identity"
	PostgreSqlVersionTableName  string = "version"
	MigrateArg                  string = "--migrate"
	InitArg                     string = "--init-identities-conf"
)
