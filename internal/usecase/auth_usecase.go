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
		return fiber.NewError(fiber.StatusBadRequest, "Invalid Google ID token")
	}

	var user *model.User

	user, err = u.userRepo.GetUserByGoogleID(googleInfo.Sub)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to query user by Google ID")
	}

	if user == nil {
		user, err = u.userRepo.GetUserByEmail(googleInfo.Email)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to query user by email")
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
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to create user")
		}
		user = newUser
	} else if user.GoogleID == "" || user.GoogleID != googleInfo.Sub {
		user.GoogleID = googleInfo.Sub
		user.IsVerified = true
		user.Name = googleInfo.Name

		if err := u.userRepo.UpdateUser(user); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to update user")
		}
	}

	tokens, err := u.generateTokenPair(user.ID, user.Role)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate token")
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
		return fiber.NewError(fiber.StatusInternalServerError, "Invalid user data")
	}

	return c.Status(fiber.StatusOK).JSON(util.ToSuccessResponse(u.buildUserRes(user)))
}

func (u *AuthUsecase) Login(c *fiber.Ctx, req *contract.LoginReq) error {
	user, err := u.userRepo.GetUserByEmail(req.Email)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to query user")
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
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate token")
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
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to query user")
	}

	if existingUser != nil {
		return fiber.NewError(fiber.StatusConflict, "Email already taken")
	}

	hashedPassword, err := util.HashPassword(req.Password)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to hash password")
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
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to create user")
	}

	verifyToken, err := u.generateVerificationToken(newUser.ID, newUser.Role)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate verification token")
	}

	if err := u.emailUsecase.SendVerificationEmail(newUser.Email, verifyToken); err != nil {
		logger.Log.Errorf("Failed to send verification email: %v", err)
	}

	return nil
}

func (u *AuthUsecase) SendVerificationEmail(email string) error {
	user, err := u.userRepo.GetUserByEmail(email)
	if err != nil {
		return err
	}

	if user.IsVerified {
		return nil
	}

	verifyToken, err := u.generateVerificationToken(user.ID, user.Role)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate verification token", err.Error())
	}

	if err := u.emailUsecase.SendVerificationEmail(user.Email, verifyToken); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to send verification email :"+err.Error())
	}

	return nil
}

func (u *AuthUsecase) VerifyEmail(token string) error {
	claims, err := util.VerifyToken(token, config.Env.JWT.Secret)
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid or expired token :"+err.Error())
	}

	if claims.Type != config.TokenTypeVerifyEmail {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid token type :"+claims.Type)
	}

	user, err := u.userRepo.GetUserByID(claims.ID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user :"+err.Error())
	}

	if user == nil {
		return fiber.NewError(fiber.StatusNotFound, "User not found")
	}

	user.IsVerified = true
	if err := u.userRepo.UpdateUser(user); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to verify email :"+err.Error())
	}

	return nil
}

func (u *AuthUsecase) ForgotPassword(req *contract.ForgotPasswordReq) error {
	user, err := u.userRepo.GetUserByEmail(req.Email)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to query user")
	}

	if user == nil {
		return fiber.NewError(fiber.StatusNotFound, "User not found")
	}

	resetToken, err := u.generateResetPasswordToken(user.ID, user.Role)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate reset token")
	}

	if err := u.emailUsecase.SendResetPasswordEmail(user.Email, resetToken); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to send reset password email")
	}

	return nil
}

func (u *AuthUsecase) ResetPassword(token string, newPassword string) error {
	claims, err := util.VerifyToken(token, config.Env.JWT.Secret)
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid or expired token")
	}

	if claims.Type != config.TokenTypeResetPassword {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid token type")
	}

	user, err := u.userRepo.GetUserByID(claims.ID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user")
	}

	if user == nil {
		return fiber.NewError(fiber.StatusNotFound, "User not found")
	}

	hashedPassword, err := util.HashPassword(newPassword)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to hash password")
	}

	if err := u.userRepo.UpdateUserPassword(user.ID, hashedPassword); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update password")
	}

	return nil
}

func (u *AuthUsecase) RefreshToken(c *fiber.Ctx, req *contract.RefreshTokenReq) error {
	claims, err := util.VerifyToken(req.RefreshToken, config.Env.JWT.Secret)
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid or expired token")
	}

	if claims.Type != config.TokenTypeRefresh {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid token type")
	}

	user, err := u.userRepo.GetUserByID(claims.ID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user")
	}

	if user == nil {
		return fiber.NewError(fiber.StatusNotFound, "User not found")
	}

	tokens, err := u.generateTokenPair(user.ID, user.Role)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate token")
	}

	res := contract.RefreshTokenRes{
		TokenRes: *tokens,
		UserRes:  u.buildUserRes(user),
	}

	return c.Status(fiber.StatusOK).JSON(util.ToSuccessResponse(res))
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
