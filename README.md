# Go Fiber Boilerplate

![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)

RESTful API boilerplate built with Go Fiber and PostgreSQL.

## Installation

Install the dependencies:

```bash
go mod tidy
```

Set the environment variables:

```bash
cp .env-example .env

# open .env and modify the environment variables (if needed)
```

## Table of Contents

- [Features](#features)
- [Commands](#commands)
- [Project Structure](#project-structure)
- [Error Handling](#error-handling)
- [Validation](#validation)
- [Authentication](#authentication)
- [Authorization](#authorization)

## Features

- **SQL database**: [PostgreSQL](https://www.postgresql.org) with [Gorm](https://gorm.io)
- **Database migrations**: with [golang-migrate](https://github.com/golang-migrate/migrate)
- **Validation**: request data validation using [Package validator](https://github.com/go-playground/validator)
- **Logging**: using custom [Zap](https://github.com/uber-go/zap)
- **Error handling**: centralized error handling mechanism
- **Sending email**: SMTP email support with Google Mail
- **Environment variables**: using [Viper](https://github.com/joho/godotenv)
- **Authentication**: Firebase Authentication and JWT
- **Security**: HTTP headers, CORS, rate limiting
- **Docker support**

## Commands

Running locally:

```bash
make start
```

Watch:

```bash
air
```

> [!NOTE]
> Make sure you have `Air` installed.\
> See 👉 [How to install Air](https://github.com/air-verse/air)

Docker:

```bash
# run docker container
make docker

# stop docker container
make docker-down

# clean docker cache
make docker-cache
```

Swagger:

```bash
# generate the swagger documentation
make swagger
```

Migration:

```bash
# Create migration
make migration-<name>

# Example
make migration-create_users_table
```

```bash
# run migration up
make migrate-up <number>

# run migration down
make migrate-down <number>
```

## Project Structure

```
internal\
 |--app\            # Application initialization and dependency injection
 |--config\         # Environment variables and configuration
 |--contract\       # Request/response contracts (DTOs)
 |--database\       # Database migrations
 |--handler\        # HTTP handlers (controller layer)
 |--middleware\     # Custom fiber middlewares
 |--model\          # Database models (data layer)
 |--repository\     # Data access layer
 |--usecase\        # Business logic (service layer)
pkg\
 |--constant\       # Application constants
 |--logger\         # Custom logger
 |--postgres\       # PostgreSQL connection
 |--util\           # Utility functions
cmd\
 |--http.go         # HTTP server command
 |--migrate.go      # Migration command
 |--root.go         # Root command
main.go             # Application entry point
```

## Error Handling

Errors are handled centrally using a custom system in `pkg/util/error.go` and Fiber's built-in error handling.

- If an error occurs, return it with `fiber.NewError(statusCode, message)`.
- The error response looks like:

```json
{
  "code": 404,
  "status": "error",
  "message": "Not found"
}
```

Example for returning a 404 error:

```go
if errors.Is(err, gorm.ErrRecordNotFound) {
	return fiber.NewError(fiber.StatusNotFound, "User not found")
}
```

The Fiber `Recover` middleware prevents crashes from panics.

## Validation

Request data is validated using [Package validator](https://github.com/go-playground/validator). Check the [documentation](https://pkg.go.dev/github.com/go-playground/validator/v10) for more details on how to write validations.

The validation is handled by the utility functions in `pkg/util/validator.go`, which checks the request data against struct tags.

## Authentication

The application uses Firebase Authentication and JWT tokens. To require authentication for certain routes, you can use the `Auth` middleware located in `internal/middleware/auth.go`.

These routes require a valid JWT access token in the Authorization request header using the Bearer schema. If the request does not contain a valid access token, an Unauthorized (401) error is thrown.

**Token Expiration**:

- Access token is valid for 30 minutes (configurable via `JWT_ACCESS_EXP_MINUTES`)
- Refresh token is valid for 30 days (configurable via `JWT_REFRESH_EXP_DAYS`)
