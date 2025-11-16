package handler

import (
	"app/internal/contract"
	"app/internal/middleware"
	"app/internal/usecase"
	"app/pkg/logger"
	"app/pkg/util"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

type AuthHandler struct {
	authUsecase *usecase.AuthUsecase
}

func NewAuthHandler(authUsecase *usecase.AuthUsecase) *AuthHandler {
	return &AuthHandler{
		authUsecase: authUsecase,
	}
}

func (h *AuthHandler) RegisterRoutes(app *fiber.App) {
	authGroup := app.Group("/v1/auth")
	authGroup.Post("/google", h.GoogleOAuth)
	authGroup.Get("/me", middleware.AuthGuard(), h.GetCurrentUser)
	authGroup.Post("/login", h.Login)
	authGroup.Post("/register", h.Register)
	authGroup.Post("/send-verification", h.SendVerificationEmail)
	authGroup.Post("/verify-email", h.VerifyEmail)
	authGroup.Post("/forgot-password", h.ForgotPassword)
	authGroup.Post("/reset-password", h.ResetPassword)
	authGroup.Post("/refresh-token", h.RefreshToken)
}

// @Tags Auth
// @Summary Login with Google
// @Description Authenticate user using Google OAuth ID token
// @Accept json
// @Produce json
// @Param request body contract.GoogleOAuthReq true "Google OAuth request"
// @Success 200 {object} util.BaseResponse{data=contract.GoogleOAuthRes}
// @Failure 400 {object} util.BaseResponse
// @Router /v1/auth/google [post]
func (h *AuthHandler) GoogleOAuth(c *fiber.Ctx) error {
	var req contract.GoogleOAuthReq
	if err := c.BodyParser(&req); err != nil {
		logger.Log.Warn("Failed to parse request body", zap.Error(err))
		return err
	}

	if err := util.ValidateStruct(&req); err != nil {
		logger.Log.Warn("Validation error", zap.Error(err))
		return err
	}

	return h.authUsecase.GoogleOAuth(c, &req)
}

// @Tags Auth
// @Summary Get current user
// @Description Get authenticated user information
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} util.BaseResponse{data=contract.UserRes}
// @Failure 401 {object} util.BaseResponse
// @Failure 500 {object} util.BaseResponse
// @Router /v1/auth/me [get]
func (h *AuthHandler) GetCurrentUser(c *fiber.Ctx) error {
	claims := middleware.GetAuthClaims(c)
	user, err := h.authUsecase.GetUserByID(claims.ID)
	if err != nil {
		logger.Log.Error("Failed to get user", zap.Error(err))
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user")
	}
	return c.Status(fiber.StatusOK).JSON(util.ToSuccessResponse(user))
}

// @Tags Auth
// @Summary Login
// @Description Authenticate user with email and password
// @Accept json
// @Produce json
// @Param request body contract.LoginReq true "Login request"
// @Success 200 {object} util.BaseResponse{data=contract.LoginRes}
// @Failure 401 {object} util.BaseResponse
// @Router /v1/auth/login [post]
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req contract.LoginReq
	if err := c.BodyParser(&req); err != nil {
		logger.Log.Warn("Failed to parse request body", zap.Error(err))
		return err
	}

	if err := util.ValidateStruct(&req); err != nil {
		logger.Log.Warn("Validation error", zap.Error(err))
		return err
	}

	return h.authUsecase.Login(c, &req)
}

// @Tags Auth
// @Summary Register
// @Description Register a new user account
// @Accept json
// @Produce json
// @Param request body contract.RegisterReq true "Register request"
// @Success 201 {object} util.BaseResponse{data=contract.RegisterRes}
// @Failure 409 {object} util.BaseResponse
// @Router /v1/auth/register [post]
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var req contract.RegisterReq
	if err := c.BodyParser(&req); err != nil {
		logger.Log.Warn("Failed to parse request body", zap.Error(err))
		return err
	}

	if err := util.ValidateStruct(&req); err != nil {
		logger.Log.Warn("Validation error", zap.Error(err))
		return err
	}

	if err := h.authUsecase.Register(&req); err != nil {
		logger.Log.Error("Failed to register user", zap.Error(err))
		return err
	}

	return c.Status(fiber.StatusCreated).JSON(util.ToSuccessResponse(contract.RegisterRes{}))
}

// @Tags Auth
// @Summary Send verification email
// @Description Send email verification link to user's email address
// @Accept json
// @Produce json
// @Param request body contract.SendVerificationEmailReq true "Send verification email request"
// @Success 200 {object} util.BaseResponse
// @Failure 400 {object} util.BaseResponse
// @Failure 500 {object} util.BaseResponse
// @Router /v1/auth/send-verification [post]
func (h *AuthHandler) SendVerificationEmail(c *fiber.Ctx) error {

	var req contract.SendVerificationEmailReq
	if err := c.BodyParser(&req); err != nil {
		logger.Log.Warn("Failed to parse request body: %v", err)
		return err
	}

	if err := util.ValidateStruct(&req); err != nil {
		logger.Log.Warn("Validation error: %v", err)
		return err
	}

	if err := h.authUsecase.SendVerificationEmail(req.Email); err != nil {
		logger.Log.Warn("Failed to send verification email: %v", err)
		return err
	}
	return c.Status(fiber.StatusOK).JSON(util.ToSuccessResponse(nil))
}

// @Tags Auth
// @Summary Verify email
// @Description Verify user email using verification token
// @Accept json
// @Produce json
// @Param token query string true "Verification token"
// @Success 200 {object} util.BaseResponse
// @Failure 400 {object} util.BaseResponse
// @Failure 401 {object} util.BaseResponse
// @Router /v1/auth/verify-email [post]
func (h *AuthHandler) VerifyEmail(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		logger.Log.Warn("Token is required")
		return fiber.NewError(fiber.StatusBadRequest, "Token is required")
	}

	return h.authUsecase.VerifyEmail(token)
}

// @Tags Auth
// @Summary Forgot password
// @Description Send password reset link to user's email address
// @Accept json
// @Produce json
// @Param request body contract.ForgotPasswordReq true "Forgot password request"
// @Success 200 {object} util.BaseResponse
// @Failure 404 {object} util.BaseResponse
// @Router /v1/auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *fiber.Ctx) error {
	var req contract.ForgotPasswordReq
	if err := c.BodyParser(&req); err != nil {
		logger.Log.Warn("Failed to parse request body: %v", err)
		return err
	}

	if err := util.ValidateStruct(&req); err != nil {
		logger.Log.Warn("Validation error: %v", err)
		return err
	}

	return h.authUsecase.ForgotPassword(&req)
}

// @Tags Auth
// @Summary Reset password
// @Description Reset user password using reset token
// @Accept json
// @Produce json
// @Param request body contract.ResetPasswordReq true "Reset password request"
// @Success 200 {object} util.BaseResponse
// @Failure 400 {object} util.BaseResponse
// @Failure 401 {object} util.BaseResponse
// @Router /v1/auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *fiber.Ctx) error {
	var req contract.ResetPasswordReq
	if err := c.BodyParser(&req); err != nil {
		logger.Log.Warn("Failed to parse request body: %v", err)
		return err
	}

	if err := util.ValidateStruct(&req); err != nil {
		logger.Log.Warn("Validation error: %v", err)
		return err
	}

	return h.authUsecase.ResetPassword(req.Token, req.Password)
}

// @Tags Auth
// @Summary Refresh token
// @Description Refresh access token using refresh token
// @Accept json
// @Produce json
// @Param request body contract.RefreshTokenReq true "Refresh token request"
// @Success 200 {object} util.BaseResponse{data=contract.RefreshTokenRes}
// @Failure 401 {object} util.BaseResponse
// @Router /v1/auth/refresh-token [post]
func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	var req contract.RefreshTokenReq
	if err := c.BodyParser(&req); err != nil {
		logger.Log.Warn("Failed to parse request body: %v", err)
		return err
	}

	if err := util.ValidateStruct(&req); err != nil {
		logger.Log.Warn("Validation error: %v", err)
		return err
	}

	return h.authUsecase.RefreshToken(c, &req)
}
