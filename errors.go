package airlock

import "github.com/martin3zra/respond"

type AccessTokenExpired struct {
	respond.ErrorDescriptor
}

func (AccessTokenExpired) Code() int {
	return 40401
}

func (AccessTokenExpired) Error() string {
	return "resource not found"
}

type InvalidCredentials struct {
	respond.ErrorDescriptor
}

func (InvalidCredentials) Code() int {
	return 40001
}

func (InvalidCredentials) Error() string {
	return "InvalidCredentials"
}

type AcceptableContent struct {
	respond.ErrorDescriptor
}

func (n *AcceptableContent) Code() int {
	return 40002
}

func (n *AcceptableContent) Error() string {
	return "AcceptableContent"
}

type RefreshTokenInvalid struct {
	respond.ErrorDescriptor
}

func (r RefreshTokenInvalid) Code() int {
	return 40102
}

func (r RefreshTokenInvalid) Error() string {
	return "RefreshTokenInvalid"
}

type AccessTokenMissing struct {
	respond.ErrorDescriptor
}

func (a *AccessTokenMissing) Code() int {
	return 40103
}

func (a *AccessTokenMissing) Error() string {
	return "AccessTokenMissing"
}

type AccessTokenRevoked struct {
	respond.ErrorDescriptor
}

func (a *AccessTokenRevoked) Code() int {
	return 40105
}

func (a *AccessTokenRevoked) Error() string {
	return "AccessTokenRevoked"
}

type NotFound struct {
	respond.ErrorDescriptor
}

func (n *NotFound) Code() int {
	return 40401
}

func (n *NotFound) Error() string {
	return "NotFound"
}
