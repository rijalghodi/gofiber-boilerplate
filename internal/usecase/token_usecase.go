package usecase

import (
	"app/internal/config"
	"app/internal/contract"
	"app/pkg/util"
	"time"
)

type TokenUsecase struct{}

func NewTokenUsecase() *TokenUsecase {
	return &TokenUsecase{}
}

func (u *TokenUsecase) GenerateTokenPair(userID string) (contract.TokenRes, error) {
	accessExpiresAt := time.Now().Add(time.Duration(config.Env.JWT.AccessExpMinutes) * time.Minute)
	accessToken, err := util.GenerateToken(userID, "", config.TokenTypeAccess, config.Env.JWT.Secret, accessExpiresAt)
	if err != nil {
		return contract.TokenRes{}, err
	}

	refreshExpiresAt := time.Now().Add(time.Duration(config.Env.JWT.RefreshExpDays) * 24 * time.Hour)
	refreshToken, err := util.GenerateToken(userID, "", config.TokenTypeRefresh, config.Env.JWT.Secret, refreshExpiresAt)
	if err != nil {
		return contract.TokenRes{}, err
	}

	return contract.TokenRes{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessExpiresAt.Format(time.RFC3339),
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiresAt.Format(time.RFC3339),
	}, nil

}
