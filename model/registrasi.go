package model

import (
	"time"

)

type UserRegis struct {
	Name     string `form:"name" validate:"required"`
	Email    string `form:"email" validate:"required,email"`
	Age      int64  `form:"age" validate:"required,numeric"`
	Password string `form:"password" validate:"required"`
}

type UserRegisRespon struct {
	ID          int        `json:"id"`
	Name        string     `json:"name"`
	Email       string     `json:"email"`
	Age         int64      `json:"age"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at"`
}