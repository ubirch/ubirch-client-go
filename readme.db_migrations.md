# Database Schema Migrations

To update the database schema to a new version, create schema migration files for postgres and sqlite as described
[here](https://github.com/golang-migrate/migrate/blob/master/MIGRATIONS.md).
> all migrations must run within a transaction, so migration files must be wrapped with `BEGIN;` and `COMMIT;`
> statements

- postgreSQL migration files can be added
  to [main/adapters/database/postgres/migrations](main/adapters/database/postgres/migrations)
- SQLite migration files can be added
  to [main/adapters/database/sqlite/migrations](main/adapters/database/sqlite/migrations)

The migration will be executed automatically on application startup or can be triggered independently using a
[CLI](https://github.com/golang-migrate/migrate/tree/master/cmd/migrate).

## Database Abstraction Layer

Steps to generate functions for database access:

- Prerequisite: [install sqlc](https://docs.sqlc.dev/en/latest/overview/install.html)

1. add postgreSQL query to `main/adapters/database/postgres/queries` and SQLite query
   to `main/adapters/database/sqlite/queries`
2. run `cd main/adapters/database && go generate`
3. extend the `Querier` interface in `main/adapters/database/querier.go` with new function
4. implement new wrapper for generated postgres function in `main/adapters/database/db_postgres.go`
   and new wrapper for generated sqlite function in `main/adapters/database/db_sqlite.go`