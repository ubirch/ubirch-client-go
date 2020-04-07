module github.com/ubirch/ubirch-go-udp-client/main

go 1.13

require (
	github.com/google/uuid v1.1.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lib/pq v1.3.0
	github.com/ubirch/ubirch-go-http-server/api v0.2.1-0.20200402131756-2c1616d3f557
	github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.0.6-0.20200407115454-9c4ecac0dd4f
)

replace github.com/ubirch/ubirch-go-http-server/api v0.2.1-0.20200402131756-2c1616d3f557 => ../../ubirch-go-http-server/api
