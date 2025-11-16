# Go Fiber Boilerplate

![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

This starter boilerplate helps you quickly build RESTful APIs for mid-sized projects using Go, Fiber, PostgreSQL, and GORM, with an Express.js-like structure.

It comes with built-in features such as JWT and Google OAuth2 authentication, request validation, Docker support, API documentation, pagination, and more. See the list below for full details.

## Installation

Install the dependencies:

```bash
go mod tidy
```

Set the environment variables:

```bash
cp .env.example .env

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
- **Environment variables**: using [Godotenv](https://github.com/joho/godotenv)
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
# This will create sql file in internnal/database/migrations, prefixed with a number
```

```bash
# run migration up
make migrate-up <number>

# run migration down
make migrate-down <number>
```

## Environment Variables

```
# =================================== #
# App
# =================================== #
APP_LOG_LEVEL=info
APP_HOST=127.0.0.1
APP_PORT=8080
APP_URL=http://localhost:8080
APP_FRONTEND_URL=http://localhost:3000


# =================================== #
# Logger
# =================================== #
LOGGER_LEVEL=debug
LOGGER_FORMAT=console # json, console
LOGGER_ENABLE_CALLER=true

# =================================== #
# Postgres
# =================================== #
POSTGRES_MIGRATION_DIRECTORY=internal/database/migrations
POSTGRES_MIGRATION_DIALECT=postgres
POSTGRES_HOST=127.0.0.1
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DBNAME=postgres
POSTGRES_PORT=5432
POSTGRES_SSL_MODE=disable
POSTGRES_MAX_OPEN_CONNS=10
POSTGRES_MAX_IDLE_CONNS=2
POSTGRES_CONN_MAX_LIFETIME=60
POSTGRES_CONN_MAX_IDLE_TIME=30


# =================================== #
# JWT
# =================================== #
JWT_SECRET=supersecretkey
JWT_ACCESS_EXP_MINUTES=15
JWT_REFRESH_EXP_DAYS=7
JWT_RESET_PASSWORD_EXP_MINUTES=5
JWT_VERIFY_EMAIL_EXP_MINUTES=5


# =================================== #
# Google Mail
# =================================== #
SMTP_GOOGLE_HOST=smtp.gmail.com
SMTP_GOOGLE_PORT=587
SMTP_GOOGLE_SENDER_NAME="Go Fiber Boilerplate"
SMTP_GOOGLE_EMAIL=your@gmail.com
SMTP_GOOGLE_PASSWORD="abcd abcd abcd abcd"

# =================================== #
# Firebase
# =================================== #
FIREBASE_SERVICE_ACCOUNT_KEY_PATH=./firebase.json

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

## Basic Authentication

Protected routes use Firebase Authentication with JWT tokens. Add the `Auth` middleware (`internal/middleware/auth.go`) to require a valid JWT access token in the `Authorization: Bearer <token>` header. Requests without a valid token get a 401 Unauthorized error.

## OAuth2 with Firebase

This application uses Firebase as an OAuth2 provider for authentication. To enable Firebase authentication in your local or production environment:

1. Go to your [Firebase Console](https://console.firebase.google.com/), select your project, and navigate to **Project Settings > Service Accounts**.
2. Click on **Generate new private key**. This will download a JSON file containing your Firebase service account credentials.
3. Save this file as `firebase.json` in the root of your project directory (or in the path specified by your configuration).
4. Ensure the path to `firebase.json` is correctly set in your environment variables (e.g., `FIREBASE_SERVICE_ACCOUNT_KEY_PATH=./firebase.json`).

The backend loads this JSON service account file to verify and authenticate JWT tokens provided by clients. Make sure to keep this file secure and do not commit it to version control.
