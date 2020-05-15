module github.com/ubirch/ubirch-client-go/main

go 1.13

require (
	github.com/go-chi/chi v4.1.0+incompatible
	github.com/google/uuid v1.1.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lib/pq v1.3.0
	github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.1.2
)

replace (
	github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.1.2 => ../../ubirch-protocol-go/ubirch
)
