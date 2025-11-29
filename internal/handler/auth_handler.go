package handler

import (
	"app/internal/config"
	"app/internal/contract"
	"app/internal/middleware"
	"app/internal/usecase"
	"app/pkg/logger"
	"app/pkg/util"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
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
	authGroup := app.Group("/auth")
	authGroup.Post("/google/login", h.GoogleLogin)
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
// @Summary Initiate Google OAuth login
// @Description Redirects to Google OAuth login page
// @Accept json
// @Produce json
// @Success 302
// @Router /auth/google/login [get]
func (h *AuthHandler) GoogleLogin(c *fiber.Ctx) error {
	// Generate a random state for CSRF protection
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		logger.Log.Error("Failed to generate state: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate state")
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	// Store state in cookie (httpOnly for security)
	c.Cookie(&fiber.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HTTPOnly: true,
		Secure:   true, // Set to true in production with HTTPS
		SameSite: "Lax",
		MaxAge:   600, // 10 minutes
		Path:     "/",
	})

	// Get Google OAuth config
	googleConfig := config.GoogleConfig()

	// Generate OAuth URL with state and additional parameters for refresh token
	// access_type=offline and prompt=consent ensure we get a refresh token
	authURL := googleConfig.AuthCodeURL(state,
		oauth2.SetAuthURLParam("access_type", "offline"),
		oauth2.SetAuthURLParam("prompt", "consent"),
	)

	// Redirect to Google OAuth
	return c.Redirect(authURL, fiber.StatusTemporaryRedirect)
}

func (h *AuthHandler) GoogleCallback(c *fiber.Ctx) error {
	state := c.Query("state")
	storedState := c.Cookies("oauth_state")

	if state != storedState {
		return fiber.NewError(fiber.StatusUnauthorized, "States don't Match!")
	}

	code := c.Query("code")
	googlecon := config.GoogleConfig()

	token, err := googlecon.Exchange(context.Background(), code)
	if err != nil {
		logger.Log.Error("Failed to exchange code: %v", err)
		return err
	}

	req, err := http.NewRequestWithContext(
		c.Context(), http.MethodGet,
		"https://www.googleapis.com/oauth2/v2/userinfo?access_token="+token.AccessToken,
		nil,
	)
	if err != nil {
		logger.Log.Error("Failed to get google user info: %v", err)
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Log.Error("Failed to do request: %v", err)
		return err
	}
	defer resp.Body.Close()

	userData, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	googleUser := new(contract.GoogleLoginReq)
	if errJSON := json.Unmarshal(userData, googleUser); errJSON != nil {
		return errJSON
	}

	res, err := h.authUsecase.LoginGoogleUser(c, googleUser)
	if err != nil {
		return err
	}

	googleLoginURL := fmt.Sprintf("%s?accessToken=%s&refreshToken=%s",
		config.Env.GoogleOAuth.ClientCallbackURI, res.TokenRes.AccessToken, res.TokenRes.RefreshToken)

	return c.Status(fiber.StatusSeeOther).Redirect(googleLoginURL)
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
// @Router /auth/me [get]
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
// @Router /auth/login [post]
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
// @Router /auth/register [post]
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
// @Router /auth/send-verification [post]
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
// @Router /auth/verify-email [post]
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
// @Router /auth/forgot-password [post]
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
// @Router /auth/reset-password [post]
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
// @Router /auth/refresh-token [post]
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
