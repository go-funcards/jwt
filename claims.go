package jwt

import (
	"errors"
	"github.com/cristalhq/jwt/v4"
	"time"
)

var (
	ErrTokenInvalidAudience  = errors.New("token has invalid audience")
	ErrTokenExpired          = errors.New("token is expired")
	ErrTokenUsedBeforeIssued = errors.New("token used before issued")
	ErrTokenNotValidYet      = errors.New("token is not valid yet")
)

type User struct {
	UserID string   `json:"user_id,omitempty"`
	Name   string   `json:"name,omitempty"`
	Email  string   `json:"email,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}

type UserClaims struct {
	jwt.RegisteredClaims
	Name  string   `json:"name,omitempty"`
	Email string   `json:"email,omitempty"`
	Roles []string `json:"roles,omitempty"`
}

func (uc UserClaims) Validate(audience string) error {
	if valid := uc.IsForAudience(audience); !valid {
		return ErrTokenInvalidAudience
	}
	if valid := uc.IsValidAt(time.Now()); !valid {
		return ErrTokenExpired
	}
	if valid := uc.IsValidIssuedAt(time.Now()); !valid {
		return ErrTokenUsedBeforeIssued
	}
	if valid := uc.IsValidNotBefore(time.Now()); !valid {
		return ErrTokenNotValidYet
	}
	return nil
}

func (uc UserClaims) User() User {
	return User{
		UserID: uc.ID,
		Name:   uc.Name,
		Email:  uc.Email,
		Roles:  uc.Roles,
	}
}
