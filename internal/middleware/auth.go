package middleware

import (
	"app/internal/config"
	"app/pkg/util"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func AuthGuard(roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Extract token from Authorization header
		token := extractToken(c)
		if token == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "Please authenticate")
		}

		// Verify and parse token
		claims, err := util.VerifyToken(token, config.Env.JWT.Secret)
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "Please authenticate")
		}

		// Check role permissions if roles are specified
		if len(roles) > 0 && !slices.Contains(roles, claims.Role) {
			return fiber.NewError(fiber.StatusForbidden, "You are not authorized to access this resource")
		}

		c.Locals("user", claims)
		return c.Next()
	}
}

func extractToken(c *fiber.Ctx) string {
	authHeader := c.Get("Authorization")
	return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
}

// GetAuthClaims retrieves authenticated user claims from context
func GetAuthClaims(c *fiber.Ctx) util.JWTClaims {
	claims, ok := c.Locals("user").(util.JWTClaims)
	if !ok {
		return util.JWTClaims{}
	}
	return claims
}
