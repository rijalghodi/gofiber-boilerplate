package logger

import (
	"log"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Log *zap.SugaredLogger

// Config holds logger configuration
type Config struct {
	Level        string // debug, info, warn, error
	Format       string // json, console
	EnableCaller bool   // show caller info
}

// Init initializes the global logger with the given configuration
func Init(cfg Config) {
	var level zapcore.Level
	switch cfg.Level {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	var config zap.Config
	if cfg.Format == "console" {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		config = zap.NewProductionConfig()
		config.EncoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	}

	config.Level = zap.NewAtomicLevelAt(level)
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.DisableCaller = !cfg.EnableCaller
	config.DisableStacktrace = true

	logger, err := config.Build()
	if err != nil {
		log.Fatalf("Could not initialize logger: %s", err.Error())
	}

	Log = logger.Sugar()
}

// InitDefault initializes the logger with default settings
func InitDefault() {
	Init(Config{
		Level:        "info",
		Format:       "json",
		EnableCaller: false,
	})
}
