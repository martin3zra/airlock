package airlock

import (
	"database/sql"

	"github.com/martin3zra/router"
)

type airLock struct {
	route *router.Routing
	auth  *auth
}

func NewAirLock(config config, route *router.Routing, db *sql.DB) airLock {
	return airLock{
		route: route,
		auth:  newAuth(config, db),
	}
}
