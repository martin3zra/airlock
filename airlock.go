package airlock

import (
	"database/sql"
	"net/http"
)

// AirLock type that expose the abilities to accept request and
// to issue JWT tokens, refresh token and expire token and
// also can response with a json format, save on cookies
// or redirect to the default or given path after a
// successful authentication.
type AirLock struct {
	route     *http.ServeMux
	auth      *auth
	wantsJSON bool
}

// NewAirLock create a new instance of AirLock type
// accept configuration, router and db object
// as params for internal task.
func NewAirLock(config Config, route *http.ServeMux, db *sql.DB) *AirLock {
	return &AirLock{
		route:     route,
		auth:      newAuth(config, db),
		wantsJSON: false,
	}
}
