package routes

import (
	"fmt"
	"membuatuser/controller"
	"membuatuser/db"
	middleware "membuatuser/middleware"
	"net/http"
	"os"

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

	user := e.Group("/users")

	user.Use(middleware.ValidateToken)

	user.GET("", controller.GetUsersController(db)) //=>untuk mengirimkan db
	user.GET("/:id", controller.GetUsersByIDController(db))
	user.POST("", controller.AddUserController(db))
	e.POST("/register", controller.RegisterController(db))
	e.POST("/login", controller.LoginCompareController(db))
	e.POST("/logout", controller.LogoutController(db))
	user.PUT("/:id", controller.EditUserController(db))
	user.DELETE("/:id", controller.DeleteUserController(db))
	user.DELETE("", controller.BulkDeleteController(db))
	return e.Start(fmt.Sprintf(":%s", os.Getenv("SERVER_PORT")))
}
