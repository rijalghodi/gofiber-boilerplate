package usecase

import (
	"context"
	"fmt"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"google.golang.org/api/option"
)

type FirebaseUsecase struct {
	auth *auth.Client
}

func NewFirebaseUsecase(ctx context.Context, serviceKeyPath string) (*FirebaseUsecase, error) {
	var app *firebase.App
	var err error

	if serviceKeyPath != "" {
		app, err = firebase.NewApp(ctx, nil, option.WithCredentialsFile(serviceKeyPath))
	} else {
		app, err = firebase.NewApp(ctx, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to initialize firebase app: %w", err)
	}

	authClient, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get firebase auth client: %w", err)
	}

	return &FirebaseUsecase{
		auth: authClient,
	}, nil
}

type GoogleTokenInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (u *FirebaseUsecase) VerifyGoogleToken(ctx context.Context, idToken string) (*GoogleTokenInfo, error) {
	token, err := u.auth.VerifyIDToken(ctx, idToken)
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
