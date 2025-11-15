package cmd

import (
	"app/internal/config"
	"app/pkg/postgres"
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	migrate "github.com/rubenv/sql-migrate"
)

// RunMigrate is the entry point for the migrate command
func RunMigrate() error {
	// Get arguments after "migrate"
	args := os.Args[2:]

	direction, version, err := validateMigrateArguments(args)
	if err != nil {
		return err
	}

	startMigration(direction, version)
	return nil
}

func startMigration(direction migrate.MigrationDirection, version int) {
	// Check confirmation for down migrations
	if direction == migrate.Down && !confirmMigrateDown(version) {
		fmt.Println("Migration aborted.")
		return
	}

	// Connect to database
	fmt.Println("Connecting to postgres...")
	pg, err := postgres.NewPostgres(postgres.PostgresConfig{
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
		fmt.Printf("Failed to connect to database: %v\n", err)
	}
	defer pg.Close()
	fmt.Println("Connected to postgres")

	// Run migration
	fmt.Println("Migrating...")
	if err := pg.Migrate(direction, version); err != nil {
		fmt.Printf("Could not migrate, err: %s\n", err.Error())
		return
	}
	fmt.Println("Migrated!")
}

func validateMigrateArguments(args []string) (direction migrate.MigrationDirection, version int, err error) {
	if len(args) != 2 {
		return direction, version, errors.New("usage: migrate [up|down] [version]")
	}

	// Parse direction
	switch args[0] {
	case "up":
		direction = migrate.Up
	case "down":
		direction = migrate.Down
	default:
		return direction, version, errors.New("direction must be 'up' or 'down'")
	}

	// Parse version
	version, err = strconv.Atoi(args[1])
	if err != nil || version <= 0 {
		return direction, version, errors.New("version must be a positive integer")
	}

	return direction, version, nil
}

func confirmMigrateDown(version int) bool {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("[WARNING] You are about to migrate down to version %d. This action cannot be undone!\n", version)
	fmt.Print("Type 'yes' to confirm: ")

	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		return false
	}

	return strings.TrimSpace(strings.ToLower(response)) == "yes"
}
