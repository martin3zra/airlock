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
				if !a.wantsJSON {
					a.invalidateCookie(w, r)
					a.Redirect(w, r, a.auth.config.redirectBackTo, http.StatusSeeOther)
					return
				}
				respond.Unauthorized(w, err)
				return
			}

			if !a.wantsJSON {
				a.invalidateCookie(w, r)
				a.Redirect(w, r, a.auth.config.redirectBackTo, http.StatusSeeOther)
				return
			}

			respond.Error(w, err)
			return
		}

		req := r.WithContext(ctx)

		h(w, req)
	}
}

func (a *AirLock) acceptMiddleware(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("accept")

		//If the accept header is empty, we don't wants json
		if len(accept) == 0 {
			a.wantsJSON = false
			h(w, r)
			return
		}

		//If the accept header value is equal to application/json
		//we wants json
		a.wantsJSON = (accept == "application/json")

		h(w, r)
	}
}
