package airlock

// Routes a registry to all expose and available routes path
// that the user can hit with a request to issue, refresh
// and revoked a given token
func (a *AirLock) Routes() {
	a.route.HandleFunc("auth/token", a.AcceptMiddleware(a.HandleLogin()))
	a.route.HandleFunc("auth/refresh", a.AcceptMiddleware(a.handleRefreshToken()))
	a.route.HandleFunc("auth/logout", a.AcceptMiddleware(a.handleLogout()))
}
