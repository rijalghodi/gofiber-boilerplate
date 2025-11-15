package cmd

import (
	"app/internal/app"
)

// @title go-fiber-boilerplate API documentation
// @version 1.0.0
// @license.name MIT
// @license.url https://github.com/indrayyana/go-fiber-boilerplate/blob/main/LICENSE
// @host localhost:3000
// @BasePath /v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Example Value: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

// RunHTTP starts the HTTP server
func RunHTTP() error {
	return app.Run()
}
