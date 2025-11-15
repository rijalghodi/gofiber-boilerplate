package config

import (
	"context"
	"fmt"
	"time"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"google.golang.org/api/option"
)

var FirebaseAuth *auth.Client

func InitFirebase(serviceKeyPath string) (*auth.Client, error) {
	ctx := context.Background()

	var app *firebase.App
	var err error

	if serviceKeyPath != "" {
		app, err = firebase.NewApp(ctx, nil, option.WithCredentialsFile(serviceKeyPath))
	} else {
		app, err = firebase.NewApp(ctx, nil)
	}
	if err != nil {
		return nil, err
	}

	return app.Auth(ctx)
}

type GoogleTokenInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func VerifyGoogleToken(idToken string) (*GoogleTokenInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token, err := FirebaseAuth.VerifyIDToken(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	email, _ := token.Claims["email"].(string)
	name, _ := token.Claims["name"].(string)
	picture, _ := token.Claims["picture"].(string)
	emailVerified, _ := token.Claims["email_verified"].(bool)

	tokenInfo := &GoogleTokenInfo{
		Sub:           token.UID,
		Email:         email,
		EmailVerified: fmt.Sprintf("%t", emailVerified),
		Name:          name,
		Picture:       picture,
	}

	return tokenInfo, nil
}
