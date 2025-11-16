package app

import (
	"app/internal/config"
	"app/internal/middleware"
	"app/pkg/logger"
	"app/pkg/postgres"
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/swagger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Run starts the application server
func Run() error {
	logger.Init(logger.Config{
		Level:        config.Env.Logger.Level,
		Format:       config.Env.Logger.Format,
		EnableCaller: config.Env.Logger.EnableCaller,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app := setupFiberApp()

	db, err := setupDatabase()
	if err != nil {
		logger.Log.Error("Failed to setup database", zap.Error(err))
		return err
	}
	defer closeDatabase(db)

	if err := setupRoutes(ctx, app, db); err != nil {
		logger.Log.Error("Failed to setup routes", zap.Error(err))
		return err
	}

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

func setupDatabase() (*gorm.DB, error) {
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
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	return db.DB, nil
}

func setupRoutes(ctx context.Context, app *fiber.App, db *gorm.DB) error {
	docs := app.Group("/docs")
	docs.Get("/*", swagger.HandlerDefault)

	InjectHTTPHandlers(ctx, app, db)
	return nil
}

func startServer(app *fiber.App, address string, errs chan<- error) {
	if err := app.Listen(address); err != nil {
		errs <- fmt.Errorf("error starting server: %w", err)
	}
}

func closeDatabase(db *gorm.DB) {
	if db == nil {
		return
	}

	sqlDB, errDB := db.DB()
	if errDB != nil {
		logger.Log.Error("Error getting database instance", zap.Error(errDB))
		return
	}

	if err := sqlDB.Close(); err != nil {
		logger.Log.Error("Error closing database connection", zap.Error(err))
	} else {
		logger.Log.Info("Database connection closed successfully")
	}
}

func handleGracefulShutdown(ctx context.Context, app *fiber.App, serverErrors <-chan error) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		logger.Log.Error("Server error", zap.Error(err))
	case <-quit:
		logger.Log.Info("Shutting down server...")
		if err := app.Shutdown(); err != nil {
			logger.Log.Error("Error during server shutdown", zap.Error(err))
		}
	case <-ctx.Done():
		logger.Log.Info("Server exiting due to context cancellation")
	}

	logger.Log.Info("Server exited")
}
