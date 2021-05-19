package vars

const (
	PostgreSql     string = "postgres"
	PostgreSqlPort int    = 5432

	Sqlite string = "sqlite3"

	SqlIdentityTableName string = "identity"
	SqlVersionTableName  string = "version"

	MigrateArg string = "--migrate"
	InitArg    string = "--init-identities-conf"

	UUIDKey      = "uuid"
	OperationKey = "operation"
	VerifyPath   = "verify"
	HashEndpoint = "hash"

	BinType  = "application/octet-stream"
	TextType = "text/plain"
	JSONType = "application/json"

	HexEncoding = "hex"

	HashLen = 32
)
