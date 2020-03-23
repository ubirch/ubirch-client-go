module main

go 1.12

require (
	github.com/eclipse/paho.mqtt.golang v1.2.0
	github.com/google/uuid v1.1.1
	github.com/paypal/go.crypto v0.1.0
	github.com/ubirch/ubirch-go-c8y-client/c8y v0.1.2
	github.com/ubirch/ubirch-go-http-server/api v0.1.0
	github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.0.2
	golang.org/x/net v0.0.0-20191021144547-ec77196f6094 // indirect
)

replace github.com/ubirch/ubirch-go-http-server/api v0.1.0 => ../../ubirch-go-http-server/api
