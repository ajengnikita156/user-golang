package middleware

import (
	"strings"

	"github.com/golang-jwt/jwt"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"

)

type claims struct {
	ID string
}

func ValidateToken(g *echo.Group) {
	var reqtoken string
	g.Use(echojwt.WithConfig(echojwt.Config{
		SigningMethod: "HS256",
		SigningKey:    []byte("secret"),
		SuccessHandler: func(c echo.Context) {
			headerToken := c.Request().Header.Get("Authorization")
			token := strings.Split(headerToken, "Bearer ")
			if len(token) > 1 {
				reqtoken = token[1]
			}
			jwtresponse, err := ClaimJwt(reqtoken)
			if err != nil {
				return
			}
			c.Set("jwt-res", jwtresponse)
		},
	}))
}

func ClaimJwt(token string) (response claims, err error) {
	var (
		jwtClaim jwt.StandardClaims
		jwtToken *jwt.Token
	)

	jwtToken, err = jwt.ParseWithClaims(token, &jwtClaim, func(jwtToken *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	if err != nil {
		return
	}

	if jwtToken.Valid {
		response = claims{
			ID: jwtClaim.Id,
		}
	}

	return
}