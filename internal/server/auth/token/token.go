// Package token выпускает и проверяет JWT access token сервера
package token

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalidConfig означает некорректную настройку token issuer
	ErrInvalidConfig = errors.New("invalid token config")

	// ErrInvalidClaims означает некорректные данные для token claims
	ErrInvalidClaims = errors.New("invalid token claims")

	// ErrInvalidToken означает некорректный access token
	ErrInvalidToken = errors.New("invalid token")

	// ErrExpiredToken означает access token с истекшим сроком действия
	ErrExpiredToken = errors.New("expired token")
)

// AccessToken содержит выпущенный token и TTL
type AccessToken struct {
	Value     string
	ExpiresAt time.Time
}

// Claims содержит проверенные данные access token
type Claims struct {
	UserID    string
	ExpiresAt time.Time
}

// jwtClaims описывает JWT claims приложения
type jwtClaims struct {
	jwt.RegisteredClaims
}

// Issuer выпускает и проверяет access token
type Issuer struct {
	secret string
	ttl    time.Duration
	now    func() time.Time
}

// NewIssuer создает issuer с текущим временем ОС
func NewIssuer(secret string, ttl time.Duration) *Issuer {
	return NewIssuerWithClock(secret, ttl, time.Now)
}

// NewIssuerWithClock создает issuer с переданной функцией времени
func NewIssuerWithClock(secret string, ttl time.Duration, now func() time.Time) *Issuer {
	if now == nil {
		now = time.Now
	}

	return &Issuer{
		secret: secret,
		ttl:    ttl,
		now:    now,
	}
}

// Issue выпускает JWT access token для пользователя
func (i *Issuer) Issue(userID string) (AccessToken, error) {
	if err := i.validateConfig(); err != nil {
		return AccessToken{}, err
	}

	userID = strings.TrimSpace(userID)
	if userID == "" {
		return AccessToken{}, fmt.Errorf("%w: user id is required", ErrInvalidClaims)
	}

	expiresAt := i.now().Add(i.ttl).UTC()

	claims := &jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(i.now().UTC()),
		},
	}

	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := rawToken.SignedString([]byte(i.secret))
	if err != nil {
		return AccessToken{}, fmt.Errorf("sign access token: %w", err)
	}

	return AccessToken{
		Value:     signedToken,
		ExpiresAt: expiresAt,
	}, nil
}

// Validate проверяет JWT access token и возвращает claims
func (i *Issuer) Validate(rawToken string) (Claims, error) {
	if err := i.validateConfig(); err != nil {
		return Claims{}, err
	}

	if strings.TrimSpace(rawToken) == "" {
		return Claims{}, ErrInvalidToken
	}

	claims := &jwtClaims{}

	parsedToken, err := jwt.ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return []byte(i.secret), nil
		},
		jwt.WithTimeFunc(i.now),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return Claims{}, ErrExpiredToken
		}

		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !parsedToken.Valid {
		return Claims{}, ErrInvalidToken
	}

	if strings.TrimSpace(claims.Subject) == "" {
		return Claims{}, ErrInvalidToken
	}

	if claims.ExpiresAt == nil {
		return Claims{}, ErrInvalidToken
	}

	return Claims{
		UserID:    claims.Subject,
		ExpiresAt: claims.ExpiresAt.UTC(),
	}, nil
}

func (i *Issuer) validateConfig() error {
	if strings.TrimSpace(i.secret) == "" {
		return fmt.Errorf("%w: secret is required", ErrInvalidConfig)
	}

	if i.ttl <= 0 {
		return fmt.Errorf("%w: ttl must be greater than zero", ErrInvalidConfig)
	}

	return nil
}
