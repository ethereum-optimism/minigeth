package rpc

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// HeaderAuthProvider is an interface for adding JWT Bearer Tokens to HTTP/WS (on the initial upgrade)
// requests to authenticated APIs.
// See https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md for details
// about the authentication scheme.
type HeaderAuthProvider interface {
	// AddAuthHeader adds an up to date Authorization Bearer token field to the header
	AddAuthHeader(header *http.Header) error
}

type JWTAuthProvider struct {
	secret []byte
}

// NewJWTAuthProvider creates a new JWT Auth Provider.
// The secret should not be empty.
func NewJWTAuthProvider(jwtsecret []byte) *JWTAuthProvider {
	return &JWTAuthProvider{secret: jwtsecret}
}

// AddAuthHeader adds a JWT Authorization token to the header
func (p *JWTAuthProvider) AddAuthHeader(header *http.Header) error {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat": time.Now().Unix(),
	})
	s, err := token.SignedString(p.secret)
	if err != nil {
		return fmt.Errorf("failed to create JWT token: %w", err)
	}
	header.Add("Authorization", "Bearer "+s)
	return nil
}
