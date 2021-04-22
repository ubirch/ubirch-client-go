package handlers

import (
	"context"
	"net/http"
	"time"
)

// contextFromRequest extracts the context from an existing http Request and
// wraps it with a timeout. This timeout indicates the maximum amount of time
// the API is allowed to serve the request including all db calls, etc.
func contextFromRequest(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 5*time.Minute)
}