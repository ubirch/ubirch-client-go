//go:generate go run github.com/kyleconroy/sqlc/cmd/sqlc@v1.16.0 compile
//go:generate sh -c "cd postgres/ && rm -f *.sql.go db.go models.go querier.go copyfrom.go"
//go:generate sh -c "cd sqlite/ && rm -f *.sql.go db.go models.go querier.go copyfrom.go"
//go:generate go run github.com/kyleconroy/sqlc/cmd/sqlc@v1.16.0 generate

package database
