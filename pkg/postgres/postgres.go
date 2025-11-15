package postgres

import (
	"database/sql"
	"fmt"
	"time"

	migrate "github.com/rubenv/sql-migrate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type PostgresConfig struct {
	MigrationDirectory string
	MigrationDialect   string
	Host               string
	User               string
	Password           string
	Port               string
	DBName             string
	SSLMode            string
	MaxOpenConns       int
	MaxIdleConns       int
	ConnMaxLifetime    int // in seconds
	ConnMaxIdleTime    int // in seconds
}

type Postgres struct {
	DB     *gorm.DB
	SQL    *sql.DB
	config PostgresConfig
}

// NewPostgres creates a new Postgres instance and establishes connection
func NewPostgres(config PostgresConfig) (*Postgres, error) {
	pg := &Postgres{
		config: config,
	}

	// Connect to database
	if err := pg.connect(); err != nil {
		return nil, err
	}

	return pg, nil
}

// connect establishes database connection and configures connection pool
func (pg *Postgres) connect() error {
	// Build DSN
	postgresDsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		pg.config.Host,
		pg.config.User,
		pg.config.Password,
		pg.config.DBName,
		pg.config.Port,
		pg.config.SSLMode,
	)

	// Open GORM connection
	db, err := gorm.Open(postgres.Open(postgresDsn), &gorm.Config{
		Logger:                 logger.Default.LogMode(logger.Warn),
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
		TranslateError:         true,
	})
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Get underlying sql.DB
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	// Ping connection
	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(pg.config.MaxOpenConns)
	sqlDB.SetMaxIdleConns(pg.config.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(time.Duration(pg.config.ConnMaxLifetime) * time.Second)
	sqlDB.SetConnMaxIdleTime(time.Duration(pg.config.ConnMaxIdleTime) * time.Second)

	// Store connections
	pg.DB = db
	pg.SQL = sqlDB

	return nil
}

// Close closes the database connection
func (pg *Postgres) Close() error {
	if pg.SQL != nil {
		return pg.SQL.Close()
	}
	return nil
}

// Migrate runs database migrations
func (pg *Postgres) Migrate(direction migrate.MigrationDirection, version int) error {
	migrations := &migrate.FileMigrationSource{
		Dir: pg.config.MigrationDirectory,
	}

	n, err := migrate.ExecVersion(pg.SQL, pg.config.MigrationDialect, migrations, direction, int64(version))
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	if n > 0 {
		fmt.Printf("Migration: Applied %d migrations\n", n)
	} else {
		fmt.Printf("Migration: No schema change\n")
	}

	return nil
}
