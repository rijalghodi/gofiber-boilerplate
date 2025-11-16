package usecase

import (
	"app/internal/config"
	"app/internal/contract"
	"app/internal/model"
	"app/internal/repository"
	"app/pkg/logger"
	"app/pkg/util"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AuthUsecase struct {
	userRepo     *repository.UserRepository
	emailUsecase *EmailUsecase
}

func NewAuthUsecase(userRepo *repository.UserRepository, emailUsecase *EmailUsecase) *AuthUsecase {
	return &AuthUsecase{
		userRepo:     userRepo,
		emailUsecase: emailUsecase,
	}
}

func (u *AuthUsecase) GoogleOAuth(c *fiber.Ctx, req *contract.GoogleOAuthReq) error {
	googleInfo, err := config.VerifyGoogleToken(req.IDToken)
	if err != nil {
		logger.Log.Warn("Failed to verify Google token", zap.Error(err))
		return fiber.NewError(fiber.StatusBadRequest, "Invalid Google ID token")
	}

	var user *model.User

	user, err = u.userRepo.GetUserByGoogleID(googleInfo.Sub)
	if err != nil {
		logger.Log.Error("Failed to query user by Google ID", zap.Error(err), zap.String("googleID", googleInfo.Sub))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if user == nil {
		user, err = u.userRepo.GetUserByEmail(googleInfo.Email)
		if err != nil {
			logger.Log.Error("Failed to query user by email", zap.Error(err), zap.String("email", googleInfo.Email))
			return fiber.NewError(fiber.StatusInternalServerError)
		}
	}

	if user == nil {
		newUser := &model.User{
			ID:         uuid.New().String(),
			Name:       googleInfo.Name,
			Email:      googleInfo.Email,
			GoogleID:   googleInfo.Sub,
			IsVerified: true,
		}
		if err := u.userRepo.CreateUser(newUser); err != nil {
			logger.Log.Error("Failed to create user", zap.Error(err), zap.String("email", googleInfo.Email))
			return fiber.NewError(fiber.StatusInternalServerError)
		}
		user = newUser
	} else if user.GoogleID == "" || user.GoogleID != googleInfo.Sub {
		user.GoogleID = googleInfo.Sub
		user.IsVerified = true
		user.Name = googleInfo.Name

		if err := u.userRepo.UpdateUser(user); err != nil {
			logger.Log.Error("Failed to update user", zap.Error(err), zap.String("userID", user.ID))
			return fiber.NewError(fiber.StatusInternalServerError)
		}
	}

	tokens, err := u.generateTokenPair(user.ID, user.Role)
	if err != nil {
		logger.Log.Error("Failed to generate token pair", zap.Error(err), zap.String("userID", user.ID))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	res := contract.GoogleOAuthRes{
		TokenRes: *tokens,
		UserRes:  u.buildUserRes(user),
	}

	return c.Status(fiber.StatusOK).JSON(util.ToSuccessResponse(res))
}

func (u *AuthUsecase) GetCurrentUser(c *fiber.Ctx) error {
	userLocal := c.Locals("user")
	if userLocal == nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Please authenticate")
	}

	user, ok := userLocal.(*model.User)
	if !ok {
		logger.Log.Error("Invalid user data type in context")
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	return c.Status(fiber.StatusOK).JSON(util.ToSuccessResponse(u.buildUserRes(user)))
}

func (u *AuthUsecase) Login(c *fiber.Ctx, req *contract.LoginReq) error {
	user, err := u.userRepo.GetUserByEmail(req.Email)
	if err != nil {
		logger.Log.Error("Failed to query user by email", zap.Error(err), zap.String("email", req.Email))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if user == nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid email or password")
	}

	if user.Password == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid email or password")
	}

	if !util.CheckPasswordHash(req.Password, user.Password) {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid email or password")
	}

	tokens, err := u.generateTokenPair(user.ID, user.Role)
	if err != nil {
		logger.Log.Error("Failed to generate token pair", zap.Error(err), zap.String("userID", user.ID))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	res := contract.LoginRes{
		TokenRes: *tokens,
		UserRes:  u.buildUserRes(user),
	}

	return c.Status(fiber.StatusOK).JSON(util.ToSuccessResponse(res))
}

func (u *AuthUsecase) Register(req *contract.RegisterReq) error {
	existingUser, err := u.userRepo.GetUserByEmail(req.Email)
	if err != nil {
		logger.Log.Error("Failed to query user by email", zap.Error(err), zap.String("email", req.Email))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if existingUser != nil {
		logger.Log.Warn("Registration attempt with existing email", zap.String("email", req.Email))
		return fiber.NewError(fiber.StatusConflict, "Email already taken")
	}

	hashedPassword, err := util.HashPassword(req.Password)
	if err != nil {
		logger.Log.Error("Failed to hash password", zap.Error(err))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	newUser := &model.User{
		ID:         uuid.New().String(),
		Name:       req.Name,
		Email:      req.Email,
		Password:   hashedPassword,
		IsVerified: false,
		Role:       "user",
	}

	if err := u.userRepo.CreateUser(newUser); err != nil {
		logger.Log.Error("Failed to create user", zap.Error(err), zap.String("email", req.Email))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	verifyToken, err := u.generateVerificationToken(newUser.ID, newUser.Role)
	if err != nil {
		logger.Log.Error("Failed to generate verification token", zap.Error(err), zap.String("userID", newUser.ID))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if err := u.emailUsecase.SendVerificationEmail(newUser.Email, verifyToken); err != nil {
		logger.Log.Error("Failed to send verification email", zap.Error(err), zap.String("email", newUser.Email))
	}

	return nil
}

func (u *AuthUsecase) SendVerificationEmail(email string) error {
	user, err := u.userRepo.GetUserByEmail(email)
	if err != nil {
		logger.Log.Error("Failed to get user by email", zap.Error(err), zap.String("email", email))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if user.IsVerified {
		return nil
	}

	verifyToken, err := u.generateVerificationToken(user.ID, user.Role)
	if err != nil {
		logger.Log.Error("Failed to generate verification token", zap.Error(err), zap.String("userID", user.ID))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if err := u.emailUsecase.SendVerificationEmail(user.Email, verifyToken); err != nil {
		logger.Log.Error("Failed to send verification email", zap.Error(err), zap.String("email", user.Email))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	return nil
}

func (u *AuthUsecase) VerifyEmail(token string) error {
	claims, err := util.VerifyToken(token, config.Env.JWT.Secret)
	if err != nil {
		logger.Log.Error("Invalid or expired verification token", zap.Error(err))
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid or expired token")
	}

	if claims.Type != config.TokenTypeVerifyEmail {
		logger.Log.Warn("Invalid token type for email verification", zap.String("tokenType", claims.Type))
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid token type")
	}

	user, err := u.userRepo.GetUserByID(claims.ID)
	if err != nil {
		logger.Log.Error("Failed to get user by ID", zap.Error(err), zap.String("userID", claims.ID))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if user == nil {
		logger.Log.Warn("User not found for email verification", zap.String("userID", claims.ID))
		return fiber.NewError(fiber.StatusNotFound, "User not found")
	}

	user.IsVerified = true
	if err := u.userRepo.UpdateUser(user); err != nil {
		logger.Log.Error("Failed to update user verification status", zap.Error(err), zap.String("userID", user.ID))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	return nil
}

func (u *AuthUsecase) ForgotPassword(req *contract.ForgotPasswordReq) error {
	user, err := u.userRepo.GetUserByEmail(req.Email)
	if err != nil {
		logger.Log.Error("Failed to query user by email", zap.Error(err), zap.String("email", req.Email))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if user == nil {
		// Don't reveal if email exists or not for security
		return nil
	}

	resetToken, err := u.generateResetPasswordToken(user.ID, user.Role)
	if err != nil {
		logger.Log.Error("Failed to generate reset password token", zap.Error(err), zap.String("userID", user.ID))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if err := u.emailUsecase.SendResetPasswordEmail(user.Email, resetToken); err != nil {
		logger.Log.Error("Failed to send reset password email", zap.Error(err), zap.String("email", user.Email))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	return nil
}

func (u *AuthUsecase) ResetPassword(token string, newPassword string) error {
	claims, err := util.VerifyToken(token, config.Env.JWT.Secret)
	if err != nil {
		logger.Log.Error("Invalid or expired reset password token", zap.Error(err))
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid or expired token")
	}

	if claims.Type != config.TokenTypeResetPassword {
		logger.Log.Warn("Invalid token type for password reset", zap.String("tokenType", claims.Type))
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid token type")
	}

	user, err := u.userRepo.GetUserByID(claims.ID)
	if err != nil {
		logger.Log.Error("Failed to get user by ID", zap.Error(err), zap.String("userID", claims.ID))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if user == nil {
		logger.Log.Warn("User not found for password reset", zap.String("userID", claims.ID))
		return fiber.NewError(fiber.StatusNotFound, "User not found")
	}

	hashedPassword, err := util.HashPassword(newPassword)
	if err != nil {
		logger.Log.Error("Failed to hash password", zap.Error(err))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if err := u.userRepo.UpdateUserPassword(user.ID, hashedPassword); err != nil {
		logger.Log.Error("Failed to update user password", zap.Error(err), zap.String("userID", user.ID))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	return nil
}

func (u *AuthUsecase) RefreshToken(c *fiber.Ctx, req *contract.RefreshTokenReq) error {
	claims, err := util.VerifyToken(req.RefreshToken, config.Env.JWT.Secret)
	if err != nil {
		logger.Log.Error("Invalid or expired refresh token", zap.Error(err))
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid or expired token")
	}

	if claims.Type != config.TokenTypeRefresh {
		logger.Log.Warn("Invalid token type for refresh", zap.String("tokenType", claims.Type))
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid token type")
	}

	user, err := u.userRepo.GetUserByID(claims.ID)
	if err != nil {
		logger.Log.Error("Failed to get user by ID", zap.Error(err), zap.String("userID", claims.ID))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	if user == nil {
		logger.Log.Warn("User not found for token refresh", zap.String("userID", claims.ID))
		return fiber.NewError(fiber.StatusNotFound, "User not found")
	}

	tokens, err := u.generateTokenPair(user.ID, user.Role)
	if err != nil {
		logger.Log.Error("Failed to generate token pair", zap.Error(err), zap.String("userID", user.ID))
		return fiber.NewError(fiber.StatusInternalServerError)
	}

	res := contract.RefreshTokenRes{
		TokenRes: *tokens,
		UserRes:  u.buildUserRes(user),
	}

	return c.Status(fiber.StatusOK).JSON(util.ToSuccessResponse(res))
}

func (u *AuthUsecase) GetUserByID(id string) (*model.User, error) {
	user, err := u.userRepo.GetUserByID(id)
	if err != nil {
		logger.Log.Error("Failed to get user by ID", zap.Error(err), zap.String("userID", id))
		return nil, fiber.NewError(fiber.StatusInternalServerError)
	}
	return user, nil
}

func (u *AuthUsecase) generateTokenPair(userID, role string) (*contract.TokenRes, error) {
	accessExpiresAt := time.Now().Add(time.Duration(config.Env.JWT.AccessExpMinutes) * time.Minute)
	accessToken, err := util.GenerateToken(userID, role, config.TokenTypeAccess, config.Env.JWT.Secret, accessExpiresAt)
	if err != nil {
		return nil, err
	}

	refreshExpiresAt := time.Now().Add(time.Duration(config.Env.JWT.RefreshExpDays) * 24 * time.Hour)
	refreshToken, err := util.GenerateToken(userID, role, config.TokenTypeRefresh, config.Env.JWT.Secret, refreshExpiresAt)
	if err != nil {
		return nil, err
	}

	return &contract.TokenRes{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessExpiresAt.Format(time.RFC3339),
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiresAt.Format(time.RFC3339),
	}, nil
}

func (u *AuthUsecase) generateVerificationToken(userID, role string) (string, error) {
	expiresAt := time.Now().Add(time.Duration(config.Env.JWT.VerifyEmailExpMinutes) * time.Minute)
	return util.GenerateToken(userID, role, config.TokenTypeVerifyEmail, config.Env.JWT.Secret, expiresAt)
}

func (u *AuthUsecase) generateResetPasswordToken(userID, role string) (string, error) {
	expiresAt := time.Now().Add(time.Duration(config.Env.JWT.ResetPasswordExpMinutes) * time.Minute)
	return util.GenerateToken(userID, role, config.TokenTypeResetPassword, config.Env.JWT.Secret, expiresAt)
}

func (u *AuthUsecase) buildUserRes(user *model.User) contract.UserRes {
	return contract.UserRes{
		ID:         user.ID,
		Email:      user.Email,
		Name:       user.Name,
		Role:       user.Role,
		IsVerified: user.IsVerified,
		CreatedAt:  user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  user.UpdatedAt.Format(time.RFC3339),
	}
}
