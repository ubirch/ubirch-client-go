module github.com/ubirch/ubirch-go-udp-client/main

go 1.13

require (
	github.com/google/uuid v1.1.1
	github.com/lib/pq v1.3.0
	github.com/paypal/go.crypto v0.1.0
	github.com/ubirch/ubirch-go-http-server/api v0.2.1-0.20200402131756-2c1616d3f557
	github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.0.4
)

replace github.com/ubirch/ubirch-go-http-server/api v0.2.1-0.20200402131756-2c1616d3f557 => ../../ubirch-go-http-server/api
