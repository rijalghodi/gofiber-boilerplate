package util

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTClaims struct {
	ID   string `json:"sub"`
	Role string `json:"role"`
	Type string `json:"type"`
}

func VerifyToken(tokenStr, secret string) (JWTClaims, error) {
	token, err := jwt.Parse(tokenStr, func(_ *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		return JWTClaims{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return JWTClaims{}, errors.New("invalid token claims")
	}

	id, ok := claims["sub"].(string)
	if !ok {
		return JWTClaims{}, errors.New("invalid token sub")
	}

	role, _ := claims["role"].(string)
	tokenType, _ := claims["type"].(string)

	return JWTClaims{ID: id, Role: role, Type: tokenType}, nil
}

func GenerateToken(userID, role, tokenType, secret string, expiresAt time.Time) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  userID,
		"role": role,
		"type": tokenType,
		"exp":  expiresAt.Unix(),
	})
	return token.SignedString([]byte(secret))
}
