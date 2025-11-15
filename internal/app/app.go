package app

import (
	"app/internal/config"
	"app/internal/middleware"
	"app/pkg/logger"
	"app/pkg/postgres"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/swagger"
	"gorm.io/gorm"
)

// Run starts the application server
func Run() error {
	logger.Init(logger.Config{
		Level: config.Env.App.LogLevel,
	})

	// Initialize Firebase
	if err := config.InitFirebase(); err != nil {
		log.Fatalf("Failed to initialize Firebase: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app := setupFiberApp()
	db := setupDatabase()
	defer closeDatabase(db)
	setupRoutes(app, db)

	address := fmt.Sprintf("%s:%d", config.Env.App.Host, config.Env.App.Port)

	// Start server and handle graceful shutdown
	serverErrors := make(chan error, 1)
	go startServer(app, address, serverErrors)
	handleGracefulShutdown(ctx, app, serverErrors)

	return nil
}

func setupFiberApp() *fiber.App {
	app := fiber.New(config.FiberConfig())

	// Middleware setup
	app.Use("/v1/auth", middleware.LimiterConfig())
	app.Use(middleware.LoggerConfig())
	app.Use(helmet.New())
	app.Use(compress.New())
	app.Use(cors.New())
	app.Use(middleware.RecoverConfig())

	return app
}

func setupDatabase() *gorm.DB {
	db, err := postgres.NewPostgres(postgres.PostgresConfig{
		MigrationDirectory: config.Env.Postgres.MigrationDirectory,
		MigrationDialect:   config.Env.Postgres.MigrationDialect,
		Host:               config.Env.Postgres.Host,
		User:               config.Env.Postgres.User,
		Password:           config.Env.Postgres.Password,
		Port:               config.Env.Postgres.Port,
		DBName:             config.Env.Postgres.DBName,
		SSLMode:            config.Env.Postgres.SSLMode,
		MaxOpenConns:       config.Env.Postgres.MaxOpenConns,
		MaxIdleConns:       config.Env.Postgres.MaxIdleConns,
		ConnMaxLifetime:    config.Env.Postgres.ConnMaxLifetime,
		ConnMaxIdleTime:    config.Env.Postgres.ConnMaxIdleTime,
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	return db.DB
}

func setupRoutes(app *fiber.App, db *gorm.DB) {

	docs := app.Group("/docs")

	docs.Get("/*", swagger.HandlerDefault)

	InjectHTTPHandlers(app, db)
}

func startServer(app *fiber.App, address string, errs chan<- error) {
	if err := app.Listen(address); err != nil {
		errs <- fmt.Errorf("error starting server: %w", err)
	}
}

func closeDatabase(db *gorm.DB) {
	sqlDB, errDB := db.DB()
	if errDB != nil {
		log.Fatalf("Error getting database instance: %v", errDB)
		return
	}

	if err := sqlDB.Close(); err != nil {
		log.Fatalf("Error closing database connection: %v", err)
	} else {
		log.Println("Database connection closed successfully")
	}
}

func handleGracefulShutdown(ctx context.Context, app *fiber.App, serverErrors <-chan error) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Fatalf("Server error: %v", err)
	case <-quit:
		log.Println("Shutting down server...")
		if err := app.Shutdown(); err != nil {
			log.Fatalf("Error during server shutdown: %v", err)
		}
	case <-ctx.Done():
		log.Println("Server exiting due to context cancellation")
	}

	log.Println("Server exited")
}
