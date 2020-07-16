package airlock

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type auth struct {
	config   config
	repo     repository
	hashable hash
}

func newAuth(config config, db *sql.DB) *auth {
	return &auth{config: config, repo: newRepository(db), hashable: newHashable()}
}

func (a *auth) Authenticate(username, password string) (*response, error) {

	userModel, err := a.repo.findByUsername(username)
	if err != nil {
		return nil, err
	}

	if !a.hashable.Check(password, userModel.GetAuthPassword()) {
		return nil, new(InvalidCredentials)
	}

	err = a.repo.eraseTokenFor(userModel.GetAuthIdentifier())
	if err != nil {
		return nil, err
	}

	accessToken, err := a.generateToken(userModel)
	if err != nil {
		return nil, err
	}

	return a.buildResponseWithRefreshToken(accessToken, userModel)
}

func (a *auth) RefreshToken(refreshToken string) (*response, error) {

	parsedToken, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return a.config.signKey, nil
	})

	if err != nil {
		return nil, new(RefreshTokenInvalid)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, new(AccessTokenMissing)
	}

	isRevoked, err := a.repo.isRefreshTokenRevoked(refreshToken)
	if err != nil {
		return nil, err
	}

	if isRevoked {
		return nil, new(AccessTokenRevoked)
	}

	expiresAt := int64((claims["expires_in"].(interface{})).(float64))
	if time.Unix(expiresAt, 0).Before(time.Now()) {
		return nil, new(AccessTokenExpired)
	}

	userID := int(claims["sub"].(float64))
	user, err := a.repo.findByID(userID)
	if err != nil {
		return nil, err
	}

	err = a.repo.Revoke(user.GetAuthIdentifier())
	if err != nil {
		return nil, err
	}

	accessToken, err := a.generateToken(user)
	if err != nil {
		return nil, err
	}

	return newResponse(accessToken, refreshToken, a.config.tokenExpireIn), nil
}

func (a *auth) VerifyToken(r *http.Request) (context.Context, error) {
	var token string
	// Get token from the Authorization header
	// format: Authorization: Bearer
	tokens, ok := r.Header["Authorization"]
	if ok && len(tokens) >= 1 {
		token = tokens[0]
		token = strings.TrimPrefix(token, "Bearer ")
	}

	if len(token) == 0 {
		return nil, new(AccessTokenMissing)
	}

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return a.config.signKey, nil
	})

	if err != nil {
		return nil, new(AccessTokenExpired)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, new(AccessTokenMissing)
	}

	expiresAt := int64((claims["expires_in"].(interface{})).(float64))
	if time.Unix(expiresAt, 0).Before(time.Now()) {
		// Flag the current token as revoked
		a.Logout(r)

		return nil, new(AccessTokenExpired)
	}

	revoked, err := a.repo.IsRevoked(token)
	if err != nil {
		return nil, err
	}

	if revoked {
		return nil, new(AccessTokenRevoked)
	}

	ID := int(claims["identifier"].(interface{}).(float64))
	ctx := context.WithValue(r.Context(), "userID", ID)
	return ctx, nil
}

func (a *auth) Logout(r *http.Request) error {
	userID := r.Context().Value("userID").(int)
	return a.repo.Revoke(userID)
}

func (a *auth) generateToken(authenticatable Authenticatable) (string, error) {

	expiresIn := time.Now().Add(time.Minute * time.Duration(a.config.tokenExpireIn)).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"type":       "Bearer",
		"expires_in": expiresIn,
		"identifier": authenticatable.GetAuthIdentifier(),
	})

	accessToken, err := token.SignedString(a.config.signKey)
	if err != nil {
		return "", err
	}

	err = a.repo.create(newTokenModel(accessToken, a.config.tokenExpireIn, authenticatable.GetAuthIdentifier()))
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

func (a *auth) buildResponseWithRefreshToken(accessToken string, authenticatable Authenticatable) (*response, error) {

	refresh, err := a.generateRefreshToken(authenticatable)
	if err != nil {
		return nil, err
	}

	data := newResponse(accessToken, refresh, a.config.tokenExpireIn)
	return data, nil
}

func (a *auth) generateRefreshToken(authenticatable Authenticatable) (string, error) {
	// Generate the refresh token
	refreshExpiresIn := time.Now().Add(time.Minute * 10080).Unix()
	refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":        authenticatable.GetAuthIdentifier(),
		"expires_in": refreshExpiresIn,
	})

	refreshToken, err := refresh.SignedString(a.config.signKey)
	if err != nil {
		return "", err
	}

	model := newRefreshTokenModel(refreshToken, a.config.tokenExpireIn, authenticatable.GetAuthIdentifier())
	err = a.repo.CreateRefreshToken(model)
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}
