package config

import (
	"context"
	"log"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"google.golang.org/api/option"
)

var FirebaseAuth *auth.Client

// InitFirebase initializes the Firebase Admin SDK
func InitFirebase() error {
	ctx := context.Background()

	var app *firebase.App
	var err error

	// If you have a service account key file path in env
	if Env.Firebase.ServiceAccountKeyPath != "" {
		opt := option.WithCredentialsFile(Env.Firebase.ServiceAccountKeyPath)
		app, err = firebase.NewApp(ctx, nil, opt)
	} else {
		// Use default credentials (for Cloud Run, GKE, etc.)
		app, err = firebase.NewApp(ctx, nil)
	}

	if err != nil {
		log.Printf("error initializing firebase app: %v", err)
		return err
	}

	// Get Auth client
	FirebaseAuth, err = app.Auth(ctx)
	if err != nil {
		log.Printf("error getting firebase auth client: %v", err)
		return err
	}

	log.Println("Firebase initialized successfully")
	return nil
}
