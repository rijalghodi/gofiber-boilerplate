package app

import (
	"app/internal/handler"
	"app/internal/repository"
	"app/internal/usecase"
	"context"

	"github.com/gofiber/fiber/v2"
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
	tokenUsecase := usecase.NewTokenUsecase()
	authUsecase := usecase.NewAuthUsecase(userRepo, emailUsecase, tokenUsecase)

	// handler
	authHandler := handler.NewAuthHandler(authUsecase)
	authHandler.RegisterRoutes(app)

}
