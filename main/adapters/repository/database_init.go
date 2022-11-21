package repository

// the following SQL statements are called upon every startup and have to be safe to be executed multiple times

var createPostgres = []string{
	`CREATE TABLE IF NOT EXISTS identity(
		uid VARCHAR(255) NOT NULL PRIMARY KEY,
		private_key BYTEA NOT NULL,
		public_key BYTEA NOT NULL,
		signature BYTEA NOT NULL,
		auth_token VARCHAR(255) NOT NULL,
		active boolean NOT NULL DEFAULT(TRUE));`,

	`CREATE TABLE IF NOT EXISTS external_identity(
		uid VARCHAR(255) NOT NULL PRIMARY KEY,
		public_key BYTEA NOT NULL);`,
}

var createSQLite = []string{
	`CREATE TABLE IF NOT EXISTS identity(
		uid TEXT NOT NULL PRIMARY KEY,
		private_key BLOB NOT NULL,
		public_key BLOB NOT NULL,
		signature BLOB NOT NULL,
		auth_token TEXT NOT NULL,
		active INTEGER NOT NULL DEFAULT(TRUE));`,

	`CREATE TABLE IF NOT EXISTS external_identity(
		uid TEXT NOT NULL PRIMARY KEY,
		public_key BLOB NOT NULL);`,
}

func (dm *DatabaseManager) CreateTables(createStatements []string) error {
	for _, create := range createStatements {
		_, err := dm.db.Exec(create)
		if err != nil {
			return err
		}
	}
	return nil
}
