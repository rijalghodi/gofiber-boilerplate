package app

import (
	"app/internal/config"
	"app/internal/handler"
	"app/internal/repository"
	"app/internal/usecase"
	"app/pkg/logger"
	"context"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func InjectHTTPHandlers(ctx context.Context, app *fiber.App, db *gorm.DB) {

	// Hello
	helloHandler := handler.NewHelloHandler()
	helloHandler.RegisterRoutes(app)

	// Health Check
	healthCheckUsecase := usecase.NewHealthCheckUsecase(db)
	healthCheckHandler := handler.NewHealthCheckController(healthCheckUsecase)
	healthCheckHandler.RegisterRoutes(app)

	// Auth setup
	userRepo := repository.NewUserRepository(db)
	emailUsecase := usecase.NewEmailUsecase()
	firebaseUsecase, err := usecase.NewFirebaseUsecase(ctx, config.Env.Firebase.ServiceAccountKeyPath)
	if err != nil {
		logger.Log.Error("Failed to initialize firebase usecase", zap.Error(err))
		panic(err)
	}
	authUsecase := usecase.NewAuthUsecase(userRepo, emailUsecase, firebaseUsecase)

	// handler
	authHandler := handler.NewAuthHandler(authUsecase)
	authHandler.RegisterRoutes(app)

}
