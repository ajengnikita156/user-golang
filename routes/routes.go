package routes

import (
	"fmt"
	"membuatuser/controller"
	"membuatuser/db"
	"net/http"
	"os"
 middleware "membuatuser/middleware"

	"github.com/labstack/echo/v4"

)
func Init() error {
	e := echo.New()
	db, err := db.Init()
	if err != nil {
		return err
	}
	defer db.Close()
	//menunda penutupan database => close

	e.GET("", func(ctx echo.Context) error {
		return ctx.JSON(http.StatusOK, map[string]string{
			"message": "Application is Running",
		})
	})

	user := e.Group("")
	middleware.ValidateToken(user) // Function untuk manggil middleware ke group routes /users

	user.GET("/users", controller.GetUsersController(db)) //=>untuk mengirimkan db
	user.GET("/getuser/:id", controller.GetUsersByIDController(db))
	user.POST("/adduser", controller.AddUserController(db))
	e.POST("/register", controller.RegisterController(db))
	e.POST("/login", controller.LoginCompareController(db))
	user.PUT("/edituser/:id", controller.EditUserController(db))
	user.DELETE("/deleteuser/:id", controller.DeleteUserController(db))
	return e.Start(fmt.Sprintf(":%s", os.Getenv("SERVER_PORT")))
}