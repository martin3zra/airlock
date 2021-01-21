package airlock

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/martin3zra/respond"
)

func (a *AirLock) wanstJson(r *http.Request) bool {
	accept := r.Header.Get("accept")

	//If the accept header is empty, we don't wants json
	if len(accept) == 0 {
		return false
	}

	//If the accept header value is equal to application/json
	//we wants json
	return (accept == "application/json")
}

func (a *AirLock) computeFormsRequest(w http.ResponseWriter, r *http.Request) *credentials {
	r.ParseForm()
	data := &credentials{}
	data.Username = r.FormValue("username")
	data.Password = r.FormValue("password")
	return data
}

func (a *AirLock) parseRequest(w http.ResponseWriter, r *http.Request) *credentials {

	if a.wanstJson(r) {
		var params = &credentials{}
		err := a.parseJsonRequest(r, params)
		if err == nil {
			return params
		}

		respond.BadRequest(w, err)
		return nil
	}

	return a.computeFormsRequest(w, r)
}

func (a *AirLock) HandleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Check the parsing method and retest specialy the one that doesn't want json on handleLogin
		params := a.parseRequest(w, r)
		if params == nil {
			return
		}

		token, err := a.auth.Authenticate(params.Username, params.Password)
		if err != nil {
			if _, ok := err.(respond.ErrorFormatter); ok {
				respond.Unauthorized(w, err)
				return
			}

			respond.Error(w, err)
			return
		}

		if a.auth.config.storeInCookie || !a.wanstJson(r) {

			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    token.Token,
				Expires:  time.Now().Add(time.Minute * time.Duration(a.auth.config.tokenExpireIn)),
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Path:     "/",
			})

			if !a.wanstJson(r) {

				http.Redirect(w, r, "", http.StatusFound)
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
		err := a.parseJsonRequest(r, params)
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
				respond.Unauthorized(w, err)
				return
			}

			respond.Error(w, err)
		}

		respond.NoContent(w)
	}
}

func (a *AirLock) parseJsonRequest(r *http.Request, params BodyContract) error {

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(params); err != nil {
		return err
	}

	if validErrs := params.Validate(); len(validErrs) > 0 {
		return errors.New(toJSON(validErrs))
	}

	return nil
}

func toJSON(m interface{}) string {
	js, err := json.Marshal(m)
	if err != nil {
		log.Fatal(err)
	}

	return strings.ReplaceAll(string(js), ",", ", ")
}
