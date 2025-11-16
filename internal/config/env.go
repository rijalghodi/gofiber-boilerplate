package config

import (
	"log"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Environment struct {
	App        App
	Logger     Logger
	Postgres   Postgres
	JWT        JWT
	SMTPGoogle SMTPGoogle
	Firebase   Firebase
}

type App struct {
	Host string `env:"APP_HOST"`
	Port int    `env:"APP_PORT"`
}

type Logger struct {
	Level        string `env:"LOGGER_LEVEL"`
	Format       string `env:"LOGGER_FORMAT"`
	EnableCaller bool   `env:"LOGGER_ENABLE_CALLER"`
}

type Postgres struct {
	MigrationDirectory string `env:"POSTGRES_MIGRATION_DIRECTORY"`
	MigrationDialect   string `env:"POSTGRES_MIGRATION_DIALECT"`
	Host               string `env:"POSTGRES_HOST"`
	Port               string `env:"POSTGRES_PORT"`
	User               string `env:"POSTGRES_USER"`
	Password           string `env:"POSTGRES_PASSWORD"`
	DBName             string `env:"POSTGRES_DBNAME"`
	SSLMode            string `env:"POSTGRES_SSL_MODE"`
	MaxOpenConns       int    `env:"POSTGRES_MAX_OPEN_CONNS" envDefault:"50"`
	MaxIdleConns       int    `env:"POSTGRES_MAX_IDLE_CONNS" envDefault:"5"`
	ConnMaxLifetime    int    `env:"POSTGRES_CONN_MAX_LIFETIME" envDefault:"120"`  // in seconds
	ConnMaxIdleTime    int    `env:"POSTGRES_CONN_MAX_IDLE_TIME" envDefault:"120"` // in seconds
}

type JWT struct {
	Secret                  string `env:"JWT_SECRET"`
	AccessExpMinutes        int    `env:"JWT_ACCESS_EXP_MINUTES"`
	RefreshExpDays          int    `env:"JWT_REFRESH_EXP_DAYS"`
	ResetPasswordExpMinutes int    `env:"JWT_RESET_PASSWORD_EXP_MINUTES"`
	VerifyEmailExpMinutes   int    `env:"JWT_VERIFY_EMAIL_EXP_MINUTES"`
}

type SMTPGoogle struct {
	Host     string `env:"SMTP_GOOGLE_HOST"`
	Port     int    `env:"SMTP_GOOGLE_PORT"`
	Sender   string `env:"SMTP_GOOGLE_SENDER_NAME"`
	Email    string `env:"SMTP_GOOGLE_EMAIL"`
	Password string `env:"SMTP_GOOGLE_PASSWORD"`
}

type Firebase struct {
	ServiceAccountKeyPath string `env:"FIREBASE_SERVICE_ACCOUNT_KEY_PATH"`
}

var Env Environment

func init() {
	_ = godotenv.Load()
	if err := env.Parse(&Env); err != nil {
		log.Fatalf("Could not parse env!, err: %s", err.Error())
	}
}
