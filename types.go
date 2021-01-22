package airlock

import (
	"net/url"
	"time"
)

// BodyContract interface that ensure his implementation have
// a validation methods, use to validate the request body
type BodyContract interface {
	Validate() url.Values
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c credentials) Validate() url.Values {
	var errs = url.Values{}

	if len(c.Username) == 0 {
		errs.Add("username", "Username can not be empty")
	}

	if len(c.Password) == 0 {
		errs.Add("password", "Password can not be empty")
	}

	return errs
}

type refreshToken struct {
	Token string `json:"token"`
}

func (r refreshToken) Validate() url.Values {
	var errs = url.Values{}

	if len(r.Token) == 0 {
		errs.Add("refresh_token", "Refresh token can not be empty")
	}

	return errs
}

type response struct {
	Type         string `json:"type"`
	Token        string `json:"token"`
	ExpireAt     int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func newResponse(accessToken, refreshToken string, expireAt int64) *response {
	return &response{
		Type:         "Bearer",
		Token:        accessToken,
		ExpireAt:     expireAt,
		RefreshToken: refreshToken,
	}
}

type tokenModel struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Token     string    `json:"token"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func newTokenModel(accessToken string, expireIn int64, identifier int) *tokenModel {
	model := new(tokenModel)
	model.Token = accessToken
	model.ExpiresAt = time.Unix(expireIn, 0)
	model.UserID = identifier
	return model
}

type refreshTokenModel struct {
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	UserID       int       `json:"user_id"`
	Revoked      bool      `json:"revoked"`
}

func newRefreshTokenModel(refreshToken string, expireIn int64, identifier int) *refreshTokenModel {
	model := new(refreshTokenModel)
	model.RefreshToken = refreshToken
	model.ExpiresAt = time.Unix(expireIn, 0)
	model.UserID = identifier
	return model
}

// Authenticatable interface that represent an authentication object
type Authenticatable interface {
	GetAuthIdentifier() int
	GetAuthIdentifierName() string
	GetAuthPassword() string
}

type user struct {
	ID       int    `json:"id"`
	Username string `json:"email"`
	Password string `json:"password"`
}

func (u user) GetAuthIdentifier() int {
	return u.ID
}

func (u user) GetAuthIdentifierName() string {
	return "email"
}

func (u user) GetAuthPassword() string {
	return u.Password
}

type keyType int

const (
	ContextUserID keyType = iota
	ContextTokenID
)
