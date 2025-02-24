package airlock

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	// This comment is for go lint
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

const encryptionKey = "some-encryption-keys-goes-here"

var db *sql.DB
var lock *AirLock

var wantsJSON = "application/json"

func StartNewAirLock(t *testing.T, storeTokenInCookie bool) {
	setEnvironment()
	db = connectDB()

	cnf := NewConfig(storeTokenInCookie, int64(17280000000), encryptionKey, nil, nil)
	route := http.NewServeMux()
	lock = NewAirLock(cnf, route, db)

	beforeEachTest(t, db)
	createUser(t, db)
}

func TestAirLock_HandleLogin(t *testing.T) {
	StartNewAirLock(t, false)

	cases := []struct {
		credentials string
		statusCode  int
		name        string
		acceptable  *string
	}{
		{
			credentials: `{"username":"jane.doe@example.com", "password":"secret"}`,
			statusCode:  http.StatusOK,
			name:        "it returns Ok when valid credentials are provided",
			acceptable:  &wantsJSON,
		},
		{
			credentials: `{"username": "not-found@example.com", "password": "secret"}`,
			statusCode:  http.StatusUnauthorized,
			name:        "it returns 401 unauthorized when invalid credentials are provided",
			acceptable:  &wantsJSON,
		},
		{
			credentials: `{"username": "", "password": ""}`,
			statusCode:  http.StatusBadRequest,
			name:        "it returns 400 bad request when empty credentials are provided",
			acceptable:  &wantsJSON,
		},
		{
			credentials: `{"username": "jane.doe@example.com", "password": "secret"}`,
			statusCode:  http.StatusSeeOther,
			name:        "it return 401 when valid credentials are provided and don't wants json",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			req := buildRequest(t, "/auth/token", test.credentials)

			if test.acceptable != nil {
				req.Header.Set("accept", *test.acceptable)
			}

			rr := post(req, lock.AcceptMiddleware(lock.HandleLogin()))

			//assert the token was generated.
			if status := rr.Code; status != test.statusCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, test.statusCode)
				t.FailNow()
			}

			if status := rr.Code; status == http.StatusOK {
				response := TransformRecorder(t, rr)
				token, ok := response["token"]
				if !ok {
					t.Errorf("handler does not returned token key")
					t.FailNow()
				}

				if len(token.(string)) == 0 {
					t.Errorf("handler returned token key empty")
					t.FailNow()
				}
			}
		})
	}
}

func TestAirLock_HandleLoginAndRedirect(t *testing.T) {
	StartNewAirLock(t, false)

	cases := []struct {
		credentials string
		statusCode  int
		name        string
		acceptable  *string
	}{
		{
			credentials: `{"username": "jane.doe@example.com", "password": "secret"}`,
			statusCode:  http.StatusFound,
			name:        "it return 302 when valid credentials are provided and don't wants json",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {

			data := url.Values{
				"username": {"jane.doe@example.com"},
				"password": {"secret"},
			}

			req, err := http.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(data.Encode()))
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			if err != nil {
				t.Errorf(err.Error())
				t.Errorf("here ")
				t.FailNow()
			}

			rr := post(req, lock.HandleLogin())
			//assert the token was generated.
			if status := rr.Code; status != test.statusCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, test.statusCode)
				t.FailNow()
			}

			if status := rr.Code; status == http.StatusOK {
				response := TransformRecorder(t, rr)
				token, ok := response["token"]
				if !ok {
					t.Errorf("handler does not returned token key")
					t.FailNow()
				}

				if len(token.(string)) == 0 {
					t.Errorf("handler returned token key empty")
					t.FailNow()
				}
			}
		})
	}
}

func TestAirLock_HandleLoginStoringInCookie(t *testing.T) {
	StartNewAirLock(t, true)

	cases := []struct {
		credentials string
		statusCode  int
		name        string
		acceptable  *string
	}{
		{
			credentials: `{"username":"jane.doe@example.com", "password":"secret"}`,
			statusCode:  http.StatusNoContent,
			name:        "it returns NoContent and cookie when valid credentials are provided",
			acceptable:  &wantsJSON,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			req := buildRequest(t, "/auth/token", test.credentials)

			if test.acceptable != nil {
				req.Header.Set("accept", *test.acceptable)
			}

			rr := post(req, lock.AcceptMiddleware(lock.HandleLogin()))

			//assert the token was generated.
			if status := rr.Code; status != test.statusCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, test.statusCode)
				t.FailNow()
			}

			var cookieTokenExists bool
			if status := rr.Code; status == http.StatusNoContent {
				cookies := rr.Result().Cookies()
				for _, cookie := range cookies {
					if cookie.Name == "token" {
						cookieTokenExists = true
					}
				}
			}

			if !cookieTokenExists {
				t.Errorf("handler returned not token cookie")
				t.FailNow()
			}
		})
	}
}

func TestAirLock_HandleRefreshToken(t *testing.T) {
	StartNewAirLock(t, false)

	req := buildRequest(t, "/auth/token", `{"username":"jane.doe@example.com", "password":"secret"}`)
	req.Header.Set("accept", wantsJSON)
	rr := post(req, lock.AcceptMiddleware(lock.HandleLogin()))
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
		t.FailNow()
	}
	response := TransformRecorder(t, rr)
	refreshToken := response["refresh_token"].(string)

	cases := []struct {
		token      string
		statusCode int
		name       string
	}{
		{
			token:      `{"token": "` + refreshToken + `"}`,
			statusCode: http.StatusOK,
			name:       "it returns Ok when valid refresh token are provided",
		},
		{
			token:      `{"token": "--invalid--"}`,
			statusCode: http.StatusUnauthorized,
			name:       "it returns 401 unauthorized when invalid token are provided",
		},
		{
			token:      `{"token": ""}`,
			statusCode: http.StatusBadRequest,
			name:       "it returns 400 bad request when empty refresh token are provided",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			req := buildRequest(t, "/auth/refresh", test.token)
			rr := post(req, lock.handleRefreshToken())

			//assert the token was generated.
			if status := rr.Code; status != test.statusCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, test.statusCode)
				t.FailNow()
			}

			if status := rr.Code; status == http.StatusOK {
				response := TransformRecorder(t, rr)
				token, ok := response["token"]
				if !ok {
					t.Errorf("handler does not returned token key")
					t.FailNow()
				}

				if len(token.(string)) == 0 {
					t.Errorf("handler returned token key empty")
					t.FailNow()
				}
			}
		})
	}
}

func TestAirLock_HandleLogout(t *testing.T) {
	StartNewAirLock(t, false)
	req := buildRequest(t, "/auth/token", `{"username":"jane.doe@example.com", "password":"secret"}`)
	req.Header.Set("accept", wantsJSON)

	rr := post(req, lock.AcceptMiddleware(lock.HandleLogin()))
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
		t.FailNow()
	}
	response := TransformRecorder(t, rr)
	token := response["token"].(string)

	req = buildRequest(t, "/auth/logout", "")
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	lock.AuthenticateMiddleware(lock.handleLogout()).ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusNoContent {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusNoContent)
		t.FailNow()
	}

}

func post(req *http.Request, handler http.HandlerFunc) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)
	return rr
}

func buildRequest(t *testing.T, url, data string) *http.Request {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func beforeEachTest(t *testing.T, db *sql.DB) {
	queries := []string{"DELETE FROM users;", "DELETE FROM oauth_access_tokens;", "DELETE FROM oauth_refresh_tokens;"}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			t.FailNow()
		}

	}
}

func createUser(t *testing.T, db *sql.DB) {
	pwd := newHashable().Make("secret")
	_, err := db.Exec("INSERT INTO users(email, password) values(?, ?)", "jane.doe@example.com", pwd)
	if err != nil {
		t.FailNow()
	}
}

func logFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func connectDB() *sql.DB {

	db, err := sql.Open(os.Getenv("DB_DRIVER"), "./arilock.db")
	logFatal(err)

	err = db.Ping()
	logFatal(err)

	return db
}

func TransformRecorder(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	responseMap := make(map[string]interface{})
	err := json.Unmarshal(rr.Body.Bytes(), &responseMap)
	if err != nil {
		t.Errorf("Cannot convert to json: %v", err)
	}

	return responseMap
}

func setEnvironment() {
	os.Setenv("DB_DRIVER", "sqlite3")
}
