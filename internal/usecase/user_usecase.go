package usecase

import (
	"app/internal/model"
	"app/internal/repository"

	"github.com/gofiber/fiber/v2"
)

type UserUsecase struct {
	userRepo *repository.UserRepository
}

func NewUserUsecase(userRepo *repository.UserRepository) *UserUsecase {
	return &UserUsecase{userRepo: userRepo}
}

func (u *UserUsecase) GetUserByID(c *fiber.Ctx, id string) (*model.User, error) {
	return u.userRepo.GetUserByID(id)
}
