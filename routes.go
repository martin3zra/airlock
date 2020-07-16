package airlock

func (a *AirLock) Routes() {
	a.route.Prefix("/auth", func() {
		a.route.Post("/token", a.HandleLogin())
		a.route.Post("/refresh", a.HandleRefreshToken())
		a.route.Post("/logout", a.AuthenticateMiddleware(a.HandleRefreshToken()))
	})
}
