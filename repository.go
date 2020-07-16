package airlock

import (
	"database/sql"
	"fmt"
)

type repository struct {
	db *sql.DB
}

func newRepository(db *sql.DB) repository {
	return repository{db: db}
}

func (r repository) findByUsername(username string) (Authenticatable, error) {
	user := new(user)

	findUserStatement := fmt.Sprintf("select id, email, password from users where %s = ?", user.GetAuthIdentifierName())

	err := r.db.QueryRow(findUserStatement, username).Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		return nil, r.handleError(err)
	}

	return user, err
}

func (r repository) findByID(id int) (Authenticatable, error) {
	findUserStatement := "select id, password from users where id = ?"
	user := new(user)
	err := r.db.QueryRow(findUserStatement, id).Scan(&user.ID, &user.Password)
	if err != nil {
		return nil, r.handleError(err)
	}

	return user, nil
}

func (r repository) eraseTokenFor(identifier int) error {
	_, err := r.db.Exec("DELETE FROM oauth_access_tokens WHERE user_id = ?", identifier)

	return err
}

func (r repository) create(model *tokenModel) error {
	_, err := r.db.Exec("INSERT INTO oauth_access_tokens(user_id, token, revoked, expires_at) VALUES(?, ?, ?, ?)",
		&model.UserID, &model.Token, &model.Revoked, &model.ExpiresAt)
	if err != nil {
		return err
	}

	return nil
}

func (r repository) CreateRefreshToken(refreshToken *refreshTokenModel) error {
	_, err := r.db.Exec("INSERT INTO oauth_refresh_tokens(user_id, refresh_token, revoked, expires_at) VALUES(?, ?, ?, ?)",
		&refreshToken.UserID, &refreshToken.RefreshToken, &refreshToken.Revoked, &refreshToken.ExpiresAt)

	if err != nil {
		return err
	}

	return nil
}

func (r repository) isRefreshTokenRevoked(token string) (bool, error) {
	var revoked bool
	err := r.db.QueryRow("SELECT revoked FROM oauth_refresh_tokens WHERE refresh_token = ?", &token).Scan(&revoked)
	if err != nil && err == sql.ErrNoRows {
		return false, nil
	}

	return revoked, err
}

func (r repository) Revoke(identifier int) error {
	revoked := true
	_, err := r.db.Exec("UPDATE oauth_access_tokens SET revoked = ? WHERE user_id = ?", &revoked, &identifier)
	if err != nil {
		return err
	}

	_, err = r.db.Exec("UPDATE oauth_refresh_tokens SET revoked = ? WHERE user_id = ?", &revoked, &identifier)

	return err
}

func (r repository) IsRevoked(token string) (bool, error) {

	var revoked bool
	err := r.db.QueryRow("SELECT revoked FROM oauth_access_tokens WHERE token = ?", &token).Scan(&revoked)
	if err != nil && err == sql.ErrNoRows {
		return false, nil
	}

	return revoked, err
}

func (r repository) handleError(err error) error {
	if err == sql.ErrNoRows {
		return new(NotFound)
	}
	return err
}
