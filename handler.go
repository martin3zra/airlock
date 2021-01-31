package airlock

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/martin3zra/respond"
)

// HandleLogin handle the user request to issue a new JWT token, it accept
// an username and password as request body and Header key as optional
// name `accept` to adknowledge how the user wants to store the
// JWT token as response
func (a *AirLock) HandleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := a.session.Get(r, "flash-session")

		params := a.parseRequest(w, r)
		if params == nil {
			return
		}

		token, err := a.auth.Authenticate(params.Username, params.Password)
		if err != nil {
			if _, ok := err.(respond.ErrorFormatter); ok {
				session.AddFlash(err.Error(), "error")
				session.Save(r, w)
				if !a.wantsJSON {
					a.Back(w, r, http.StatusSeeOther)
					return
				}

				respond.Unauthorized(w, err)
				return
			}

			if !a.wantsJSON {
				session.AddFlash(err.Error(), "error")
				session.Save(r, w)
				a.Back(w, r, http.StatusSeeOther)
				return
			}

			respond.Error(w, err)
			return
		}

		if a.auth.config.storeInCookie || !a.wantsJSON {

			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    token.Token,
				Expires:  time.Now().Add(time.Minute * time.Duration(a.auth.config.tokenExpireIn)),
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Path:     "/",
			})

			if !a.wantsJSON {

				a.Redirect(w, r, a.auth.config.redirectTo, http.StatusFound)
				return
			}

			respond.NoContent(w)
			return
		}

		respond.OK(w, token)
	}
}

func (a *AirLock) handleRefreshToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params := &refreshToken{}
		err := a.parseJSONRequest(r, params)
		if err != nil {
			respond.BadRequest(w, err)
			return
		}

		token, err := a.auth.RefreshToken(params.Token)
		if err != nil {
			if _, ok := err.(respond.ErrorFormatter); ok {
				respond.Unauthorized(w, err)
				return
			}

			respond.Error(w, err)
		}

		respond.OK(w, token)
	}
}

func (a *AirLock) handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		err := a.auth.Logout(r)
		if err != nil {
			if _, ok := err.(respond.ErrorFormatter); ok {
				//Flash message here
				if !a.wantsJSON {
					a.Back(w, r, http.StatusInternalServerError)
					return
				}

				respond.Unauthorized(w, err)
				return
			}

			if !a.wantsJSON {
				a.Back(w, r, http.StatusInternalServerError)
				return
			}

			respond.Error(w, err)
		}

		if !a.wantsJSON {
			a.invalidateCookie(w, r)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		respond.NoContent(w)
	}
}

func toJSON(m interface{}) string {
	js, err := json.Marshal(m)
	if err != nil {
		log.Fatal(err)
	}

	return strings.ReplaceAll(string(js), ",", ", ")
}
