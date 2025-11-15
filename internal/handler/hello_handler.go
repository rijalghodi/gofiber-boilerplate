package handler

import (
	"github.com/gofiber/fiber/v2"
)

type HelloHandler struct{}

func NewHelloHandler() *HelloHandler {
	return &HelloHandler{}
}

func (h *HelloHandler) RegisterRoutes(app *fiber.App) {
	app.Get("/hello", h.Hello)
}

// @Tags Hello
// @Summary Hello
// @Description Simple hello world endpoint
// @Accept json
// @Produce text/plain
// @Success 200 {string} string "Hello, World!"
// @Router /hello [get]
func (h *HelloHandler) Hello(c *fiber.Ctx) error {
	return c.SendString("Hello, World!")
}
