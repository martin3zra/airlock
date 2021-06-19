package airlock

// Routes a registry to all expose and available routes path
// that the user can hit with a request to issue, refresh
// and revoked a given token
func (a *AirLock) Routes() {
	a.route.Prefix("auth", func() {
		a.route.Middleware(a.AcceptMiddleware).Group(func() {
			a.route.Post("token", a.HandleLogin())
			a.route.Post("refresh", a.handleRefreshToken())
			a.route.Post("logout", a.AuthenticateMiddleware(a.handleLogout()))
		})
	})
}
