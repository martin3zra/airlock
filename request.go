package airlock

import (
	"net/http"
	"strings"
)

func (a *auth) tokenFromRequest(r *http.Request) (string, error) {
	var token string
	if a.config.storeInCookie {
		cookie, err := r.Cookie("token")
		if err != nil {
			return "", new(AccessTokenMissing)
		}
		token = cookie.Value
	} else {
		tokens, ok := r.Header["Authorization"]
		if ok && len(tokens) >= 1 {
			token = tokens[0]
			token = strings.TrimPrefix(token, "Bearer ")
		}
	}

	if len(token) == 0 {
		return "", new(AccessTokenMissing)
	}

	return token, nil
}
