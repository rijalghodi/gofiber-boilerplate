package config

import (
	"app/pkg/util"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v2"
)

func FiberConfig() fiber.Config {
	return fiber.Config{
		CaseSensitive: true,
		ServerHeader:  "Memr",
		AppName:       "Memr API",
		ErrorHandler:  util.ErrorHandler,
		JSONEncoder:   sonic.Marshal,
		JSONDecoder:   sonic.Unmarshal,
	}
}
