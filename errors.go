package airlock

import "github.com/martin3zra/respond"

// AccessTokenExpired type an error description for expired token
type AccessTokenExpired struct {
	respond.ErrorDescriptor
}

// Code a int value that correspond to the AccessTokenExpired type
func (AccessTokenExpired) Code() int {
	return 40401
}

// Error a string value that correspond to the AccessTokenExpired type
func (AccessTokenExpired) Error() string {
	return "resource not found"
}

// InvalidCredentials type an error description for invalid credentials
type InvalidCredentials struct {
	respond.ErrorDescriptor
}

// Code a int value that correspond to the InvalidCredentials type
func (InvalidCredentials) Code() int {
	return 40001
}

// Error a string value that correspond to the InvalidCredentials type
func (InvalidCredentials) Error() string {
	return "InvalidCredentials"
}

// RefreshTokenInvalid type an error description for invalid refresh token
type RefreshTokenInvalid struct {
	respond.ErrorDescriptor
}

// Code a int value that correspond to the RefreshTokenInvalid type
func (r RefreshTokenInvalid) Code() int {
	return 40102
}

// Error a string value that correspond to the RefreshTokenInvalid type
func (r RefreshTokenInvalid) Error() string {
	return "RefreshTokenInvalid"
}

// AccessTokenMissing type an error description for when the access token is missing
type AccessTokenMissing struct {
	respond.ErrorDescriptor
}

// Code a int value that correspond to the AccessTokenMissing type
func (a *AccessTokenMissing) Code() int {
	return 40103
}

// Error a string value that correspond to the AccessTokenMissing type
func (a *AccessTokenMissing) Error() string {
	return "AccessTokenMissing"
}

// AccessTokenRevoked type an error description for when the access token is has been revoked
type AccessTokenRevoked struct {
	respond.ErrorDescriptor
}

// Code a int value that correspond to the AccessTokenRevoked type
func (a *AccessTokenRevoked) Code() int {
	return 40105
}

// Error a string value that correspond to the AccessTokenRevoked type
func (a *AccessTokenRevoked) Error() string {
	return "AccessTokenRevoked"
}

// NotFound type an error description for when a resource is not found
type NotFound struct {
	respond.ErrorDescriptor
}

// Code a int value that correspond to the NotFound type
func (n *NotFound) Code() int {
	return 40401
}

// Error a string value that correspond to the NotFound type
func (n *NotFound) Error() string {
	return "NotFound"
}
