package model

import "time"

type User struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Email       string     `json:"email"`
	Password    string     `json:"-"` // Hidden from JSON, stores hashed password
	IsVerified  bool       `json:"is_verified"`
	GoogleImage *string    `json:"google_image"`
	Role        string     `json:"role"`
	GoogleID    string     `json:"google_id"`
	CreatedAt   time.Time  `gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt   time.Time  `gorm:"default:CURRENT_TIMESTAMP"`
	DeletedAt   *time.Time `gorm:"index"`
}
