package handlers

import (
	"github.com/ubirch/ubirch-client-go/main/config"
)

// Later we can add authenticator
type Globals struct {
	Config  config.Config
	Version string
}