module main

go 1.13

require (
	github.com/google/uuid v1.1.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/paypal/go.crypto v0.1.0
	github.com/ubirch/ubirch-go-http-server/api v0.1.1-0.20200324152634-d9f1d992d4da
	github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.0.2
)

//replace github.com/ubirch/ubirch-go-http-server/api v0.1.0 => ../../ubirch-go-http-server/api
