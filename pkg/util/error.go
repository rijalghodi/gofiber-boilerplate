package util

import (
	"errors"

	"github.com/gofiber/fiber/v2"
)

func ErrorHandler(c *fiber.Ctx, err error) error {
	if errorsMap := CustomErrorMessages(err); len(errorsMap) > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ToErrorResponse("Bad Request", errorsMap))
	}

	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		return c.Status(fiberErr.Code).JSON(ToErrorResponse(fiberErr.Message, nil))
	}

	return c.Status(fiber.StatusInternalServerError).JSON(ToErrorResponse("Internal Server Error", nil))
}

func NotFoundHandler(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotFound).JSON(ToErrorResponse("Endpoint Not Found", nil))
}
