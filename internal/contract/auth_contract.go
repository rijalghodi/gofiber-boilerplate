package contract

type UserRes struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	IsVerified bool   `json:"isVerified"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}

type TokenRes struct {
	AccessToken           string `json:"accessToken"`
	AccessTokenExpiresAt  string `json:"accessTokenExpiresAt"`
	RefreshToken          string `json:"refreshToken"`
	RefreshTokenExpiresAt string `json:"refreshTokenExpiresAt"`
}

type GoogleOAuthReq struct {
	IDToken string `json:"idToken" validate:"required"`
}

type GoogleOAuthRes struct {
	TokenRes
	UserRes
}

type LoginReq struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,password"`
}

type RegisterReq struct {
	Email    string `json:"email" validate:"required,email"`
	Name     string `json:"name" validate:"required"`
	Password string `json:"password" validate:"required,password"`
}

type LoginRes struct {
	TokenRes
	UserRes
}

type RegisterRes struct {
	UserRes
}

type SendVerificationEmailReq struct {
	Email string `json:"email" validate:"required,email"`
}

type ForgotPasswordReq struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordReq struct {
	Password string `json:"password" validate:"required,password"`
	Token    string `json:"token" validate:"required"`
}

type VerifyEmailReq struct {
	Token string `json:"token" validate:"required"`
}

type RefreshTokenReq struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

type RefreshTokenRes struct {
	TokenRes
	UserRes
}
