package database

import (
	"database/sql"
)

func NewQuerier(dbConn *sql.DB, driverName string) Querier {
	switch driverName {
	case PostgreSQL:
		return NewPostgresDatabase(dbConn)
	case SQLite:
		return NewSqliteDatabase(dbConn)
	default:
		return nil
	}
}
