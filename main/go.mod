module main

go 1.12

require (
	github.com/eclipse/paho.mqtt.golang v1.2.0
	github.com/google/uuid v1.1.1
	github.com/paypal/go.crypto v0.1.0
	github.com/ubirch/ubirch-protocol-go/ubirch v1.0.1
	golang.org/x/net v0.0.0-20191009170851-d66e71096ffb // indirect
)

replace github.com/ubirch/ubirch-protocol-go/ubirch v1.0.1 => ../../ubirch-protocol-go/ubirch
