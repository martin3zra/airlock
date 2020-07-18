package airlock

func (a *AirLock) Routes() {
	a.route.Prefix("auth", func() {
		a.route.Post("token", a.handleLogin())
		a.route.Post("refresh", a.handleRefreshToken())
		a.route.Post("logout", a.AuthenticateMiddleware(a.handleLogout()))
	})
}
