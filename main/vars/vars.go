package vars

const (
	PostgreSql                  string = "postgres"
	PostgreSqlPort              int    = 5432
	PostgreSqlIdentityTableName string = "identity"
	PostgreSqlVersionTableName  string = "version"
	MigrateArg                  string = "--migrate"
	InitArg                     string = "--init-identities-conf"

	UUIDKey          = "uuid"
	OperationKey     = "operation"
	VerifyPath       = "verify"
	HashEndpoint     = "hash"
	RegisterEndpoint = "register"
	SigningPath       = "sign"
	ChainingPath     = "chain"

	BinType  = "application/octet-stream"
	TextType = "text/plain"
	JSONType = "application/json"

	HexEncoding = "hex"

	HashLen = 32
)
