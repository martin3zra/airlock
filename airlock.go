package airlock

import (
	"database/sql"

	"github.com/martin3zra/router"
)

type AirLock struct {
	route *router.Routing
	auth  *auth
}

func NewAirLock(config config, route *router.Routing, db *sql.DB) *AirLock {
	return &AirLock{
		route: route,
		auth:  newAuth(config, db),
	}
}
