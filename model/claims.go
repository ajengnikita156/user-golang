package model

import (
	"github.com/golang-jwt/jwt/v4"

)

type MyClaims struct {
	jwt.StandardClaims
	Id int `json:"id"`
	// jwt.RegisteredClaims
}