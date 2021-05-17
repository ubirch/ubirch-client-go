package vars

const (
	PostgreSql                  string = "postgres"
	PostgreSqlPort              int    = 5432
	PostgreSqlIdentityTableName string = "identity"
	PostgreSqlVersionTableName  string = "version"
	MigrateArg                  string = "--migrate"
	InitArg                     string = "--init-identities-conf"

	MySql                  string = "mysql"
	MySqlPort              int    = 3306

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
