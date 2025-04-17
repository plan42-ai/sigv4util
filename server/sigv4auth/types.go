package sigv4auth

import (
	"fmt"
	"net/http"
)

type MessageType string

const (
	AuthenticationError MessageType = "AuthenticationError"
	BadAuthHeader       MessageType = "BadAuthHeader"
	MultipleAuthHeaders MessageType = "MultipleAuthHeaders"
	NotAuthorized       MessageType = "NotAuthorized"
)

type Error struct {
	StatusCode  int
	MessageType MessageType
	Message     string
}

func (e Error) Error() string {
	return e.Message
}

func NewAuthenticationError() error {
	return &Error{
		StatusCode:  http.StatusUnauthorized,
		MessageType: AuthenticationError,
		Message:     "unable to authenticate client",
	}
}

func NewBadAuthHeaderError(headerName string) error {
	return &Error{
		StatusCode:  http.StatusUnauthorized,
		MessageType: BadAuthHeader,
		Message:     fmt.Sprintf("invalid '%v' header", headerName),
	}
}

func NewMultipleAuthHeadersError(headerName string) error {
	return &Error{
		StatusCode:  http.StatusUnauthorized,
		MessageType: MultipleAuthHeaders,
		Message:     fmt.Sprintf("multiple '%v' headers supplied", headerName),
	}
}

func NewNotAuthorizedError(message string) *Error {
	return &Error{
		StatusCode:  http.StatusForbidden,
		MessageType: NotAuthorized,
		Message:     message,
	}
}

type AWSPrincipal struct {
	ARN string
}
