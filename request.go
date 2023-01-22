package airlock

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/martin3zra/respond"
)

func (a *auth) tokenFromRequest(r *http.Request) (string, error) {
	var token string
	tokens, ok := r.Header["Authorization"]
	if ok && len(tokens) >= 1 {
		token = tokens[0]
		token = strings.TrimPrefix(token, "Bearer ")
	}

	if len(token) == 0 {
		cookie, err := r.Cookie("token")
		if err != nil {
			return "", new(AccessTokenMissing)
		}
		token = cookie.Value
		if len(token) == 0 {
			return "", new(AccessTokenMissing)
		}
	}

	return token, nil
}

func (a *AirLock) invalidateCookie(w http.ResponseWriter, r *http.Request) {

	cookie := &http.Cookie{
		Name:     "token",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Expires:  time.Now().Add(-1 * time.Minute),
	}

	http.SetCookie(w, cookie)
	r.AddCookie(cookie)
}

func (a *AirLock) Redirect(w http.ResponseWriter, r *http.Request, redirectTo string, status int) {
	http.Redirect(w, r, redirectTo, status)
}

func (a *AirLock) computeFormsRequest(w http.ResponseWriter, r *http.Request) *credentials {
	r.ParseForm()
	data := &credentials{}
	data.Username = r.FormValue("username")
	data.Password = r.FormValue("password")
	return data
}

func (a *AirLock) parseRequest(w http.ResponseWriter, r *http.Request) *credentials {

	if a.wantsJSON {
		var params = &credentials{}
		err := a.parseJSONRequest(r, params)
		if err == nil {
			return params
		}

		respond.BadRequest(w, err)
		return nil
	}

	return a.computeFormsRequest(w, r)
}

func (a *AirLock) Back(w http.ResponseWriter, r *http.Request, status int) {

	a.Redirect(w, r, a.auth.config.redirectBackTo, status)
}

func (a *AirLock) parseJSONRequest(r *http.Request, params BodyContract) error {

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(params); err != nil {
		return err
	}

	if validErrs := params.Validate(); len(validErrs) > 0 {
		return errors.New(toJSON(validErrs))
	}

	return nil
}
