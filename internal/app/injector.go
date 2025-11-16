package app

import (
	"app/internal/handler"
	"app/internal/repository"
	"app/internal/usecase"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func InjectHTTPHandlers(app *fiber.App, db *gorm.DB) {

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
	authUsecase := usecase.NewAuthUsecase(userRepo, emailUsecase)

	// handler
	authHandler := handler.NewAuthHandler(authUsecase)
	authHandler.RegisterRoutes(app)

}
