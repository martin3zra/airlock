package airlock

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/martin3zra/respond"
)

func (a *airLock) HandleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var params = &credentials{}
		if !a.computedParams(w, r, params) {
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

		respond.OK(w, token)
	}
}

func (a *airLock) HandleRefreshToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params := &refreshToken{}
		if !a.computedParams(w, r, params) {
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

func (a *airLock) HandleLogout() http.HandlerFunc {
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

func (a *airLock) computedParams(w http.ResponseWriter, r *http.Request, params BodyContract) bool {

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(params); err != nil {
		respond.BadRequest(w, err)
		return false
	}

	if validErrs := params.Validate(); len(validErrs) > 0 {
		respond.BadRequest(w, errors.New(toJSON(validErrs)))
		return false
	}

	return true
}

func toJSON(m interface{}) string {
	js, err := json.Marshal(m)
	if err != nil {
		log.Fatal(err)
	}

	return strings.ReplaceAll(string(js), ",", ", ")
}
