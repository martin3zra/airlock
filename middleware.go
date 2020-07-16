package airlock

import (
	"net/http"

	"github.com/martin3zra/respond"
)

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
