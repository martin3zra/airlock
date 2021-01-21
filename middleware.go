package airlock

import (
	"net/http"

	"github.com/martin3zra/respond"
)

// AuthenticateMiddleware a request interceptor that ensure that the given
// JWT token is still valid otherwise stop the request propagation and
// respond with Unauthorized response
func (a *AirLock) AuthenticateMiddleware(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, err := a.auth.VerifyToken(r)
		if err != nil {
			if _, ok := err.(respond.ErrorFormatter); ok {
				respond.Unauthorized(w, err)
				return
			}

			respond.Error(w, err)
			return
		}

		req := r.WithContext(ctx)

		h(w, req)
	}
}
