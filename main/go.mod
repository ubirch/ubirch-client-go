module github.com/ubirch/ubirch-client-go/main

go 1.16

require (
	github.com/go-chi/chi v1.5.4
	github.com/go-chi/cors v1.2.0 // indirect
	github.com/google/uuid v1.2.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lib/pq v1.10.1
	github.com/prometheus/client_golang v1.11.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/ubirch/ubirch-client-go/lib/httphelper v2.0.11-0.20210620115726-ba100f284f8f+incompatible // indirect
	github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.2.6-0.20210428143952-0a0718362749
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
)

replace github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.2.6-0.20210428143952-0a0718362749 => ../../ubirch-protocol-go/ubirch
