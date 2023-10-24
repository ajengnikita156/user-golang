package controller

import (
	"database/sql"
	"fmt"
	"membuatuser/helpers"
	"membuatuser/middleware"
	"net/http"
	// "strconv"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"

)

type User struct {
	ID          int        `json:"id"`
	Name        string     `json:"name"`
	Email       string     `json:"email"`
	Age         int64      `json:"age"`
	Address     *string    `json:"address"`
	PhoneNumber *string    `json:"phone_number"`
	Gender      *string    `json:"gender"`
	Status      *string    `json:"status"`
	City        *string    `json:"city"`
	Province    *string    `json:"province"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at"`
	//bisa menggunakan omitempty //=> kalo data gaada ga ditampilkan
	//menggunakan struc dan pointer agar hasilnya null
}

type UserReq struct {
	Name        string `form:"name" validate:"required"`
	Email       string `form:"email" validate:"required,email"`
	Age         int64  `form:"age" validate:"required,numeric"`
	Password    string `form:"password" validate:"required"`
	Address     string `form:"address" validate:"required"`
	PhoneNumber string `form:"phone_number" validate:"required"`
	Gender      string `form:"gender" validate:"required"`
	Status      string `form:"status" validate:"required"`
	City        string `form:"city" validate:"required"`
	Province    string `form:"province" validate:"required"`
}

type UserRegis struct {
	Name     string `form:"name" validate:"required"`
	Email    string `form:"email" validate:"required,email"`
	Age      int64  `form:"age" validate:"required,numeric"`
	Password string `form:"password" validate:"required"`
}

type UserRegisRespon struct {
	ID        int        `json:"id"`
	Name      string     `json:"name"`
	Email     string     `json:"email"`
	Age       int64      `json:"age"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at"`
}

type UserLogin struct {
	Email    string `form:"email" validate:"required,email"`
	Password string `form:"password" validate:"required"`
}

type UserLogRespon struct {
	ID        int        `json:"id"`
	Name      string     `json:"name"`
	Email     string     `json:"email"`
	Age       int64      `json:"age"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at"`
	Password  string     `json:"-"`
}

type MyClaims struct {
	jwt.StandardClaims
	ID int `json:"id"`
}

type Claims struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	jwt.StandardClaims
}

type BulkDeleteRequest struct {
	ID []int `json:"id"`
}

func GetUsersController(db *sqlx.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var users []User

		const query = `SELECT users.id, users.name, users.email, users.age, detail_users.address, detail_users.phone_number, detail_users.gender, detail_users.status, detail_users.city, detail_users.province, users.created_at, users.updated_at
		FROM users
		LEFT JOIN detail_users
		ON users.id = detail_users.id_user`
		rows, err := db.Query(query)
		if err != nil {
			return err
		}

		for rows.Next() {
			var user User
			var updatedAt sql.NullTime //=>bernilai nol (NULL)
			// scan untuk menyimpan data
			err = rows.Scan(
				&user.ID,
				&user.Name,
				&user.Email,
				&user.Age,
				&user.Address,
				&user.PhoneNumber,
				&user.Gender,
				&user.Status,
				&user.City,
				&user.Province,
				&user.CreatedAt,
				&updatedAt,
			)
			if updatedAt.Valid {
				user.UpdatedAt = &updatedAt.Time
			}
			if err != nil {
				return err
			}
			users = append(users, user)
			//append => untuk menambahkan data
		}

		user := c.Get("jwt-res")
		claims := user.(middleware.JWTClaim)
		id := claims.ID
		email := claims.Email
		fmt.Println(id, email)

		return c.JSON(http.StatusOK, map[string]interface{}{
			"Message": "Successfully displays user data",
			"data":    users,
		})
	}
}

func GetUsersByIDController(db *sqlx.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		userID := c.Param("id")
		var user User

		query :=
			`SELECT users.id, users.name, users.email, users.age, detail_users.address, detail_users.phone_number, detail_users.gender, detail_users.status, detail_users.city, detail_users.province, users.created_at, users.updated_at
			FROM users
			LEFT JOIN detail_users
			ON users.id = detail_users.id_user WHERE users.id = $1 `

		row := db.QueryRowx(query, userID)

		var updatedAt sql.NullTime
		err := row.Scan(
			&user.ID,
			&user.Name,
			&user.Email,
			&user.Age,
			&user.Address,
			&user.PhoneNumber,
			&user.Gender,
			&user.Status,
			&user.City,
			&user.Province,
			&user.CreatedAt,
			&updatedAt,
		)
		if updatedAt.Valid {
			user.UpdatedAt = &updatedAt.Time
		}

		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]interface{}{
				"Message": "Data ID tidak ditemukan",
			})
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"Message": "Displaying User Data with id",
			"data":    user,
		})
	}
}

func AddUserController(db *sqlx.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var request UserReq
		var user User
		validate := validator.New()

		err := c.Bind(&request) //=>mencocokan data di struct
		//bind =>mengambil data dari input,mengisi var request ,dan mencocokan di struct userreq
		if err != nil {
			return err
		}

		//function validator
		err = validate.Struct(request)
		if err != nil {
			var errormassage []string
			validationErrors := err.(validator.ValidationErrors)
			for _, err := range validationErrors {
				errormassage = append(errormassage, err.Error())
			}
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"message": errormassage,
			})
		}

		//function hasspassword
		password, err := helpers.HashPassword(request.Password)
		if err != nil {
			return err
		}

		query := `
		INSERT INTO users (name, email, age, created_at, password)
		VALUES ( $1, $2, $3, now(), $4)
		RETURNING id, name, email, age, created_at `

		row := db.QueryRowx(query, request.Name, request.Email, request.Age, password) //=>mengambil data yang sama di struct
		err = row.Scan(
			&user.ID,
			&user.Name,
			&user.Email,
			&user.Age,
			&user.CreatedAt,
		)

		if err != nil {
			return err
		}

		query2 := `
		INSERT INTO detail_users (id_user, address, phone_number, gender, status, city, province, created_at)
		VALUES ( $1, $2, $3, $4, $5, $6, $7, NOW() )
		RETURNING address, phone_number, gender, status, city, province `

		row2 := db.QueryRowx(query2, user.ID, request.Address, request.PhoneNumber, request.Gender, request.Status, request.City, request.Province) //=>mengambil data yang sama di struct
		err = row2.Scan(
			&user.Address,
			&user.PhoneNumber,
			&user.Gender,
			&user.Status,
			&user.City,
			&user.Province,
		)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"Message": "Successfully Added New user Data",
			"data":    user,
		})
	}
}

func EditUserController(db *sqlx.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		userID := c.Param("id")
		var request UserReq
		var user User
		validate := validator.New()

		err := c.Bind(&request)
		//=>bind mengaitkan
		if err != nil {
			return err
		}

		//function validator
		err = validate.Struct(request)
		if err != nil {
			var errormassage []string
			validationErrors := err.(validator.ValidationErrors)
			for _, err := range validationErrors {
				errormassage = append(errormassage, err.Error())
			}
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"message": errormassage,
			})
		}

		//function hasspassword
		password, err := helpers.HashPassword(request.Password)
		if err != nil {
			return err
		}

		query := `UPDATE users SET name = $1, email = $2, age = $3, updated_at = now(), password = $5 WHERE id = $4
		RETURNING id, name, email, age, created_at, updated_at `

		row := db.QueryRowx(query, request.Name, request.Email, request.Age, userID, password)
		err = row.Scan(
			&user.ID,
			&user.Name,
			&user.Email,
			&user.Age,
			&user.CreatedAt,
			&user.UpdatedAt,
		)

		if err != nil {
			return err
		}

		query2 := `UPDATE detail_users SET address = $1, phone_number = $2, gender = $3, status = $4,
			city = $5, province = $6, updated_at = now() WHERE id_user = $7
			RETURNING address, phone_number, gender, status, city, province `

		row2 := db.QueryRowx(query2, request.Address, request.PhoneNumber, request.Gender, request.Status, request.City, request.Province, userID)

		err = row2.Scan(
			&user.Address,
			&user.PhoneNumber,
			&user.Gender,
			&user.Status,
			&user.City,
			&user.Province,
		)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"Message": "Successfully edited Data ",
			"data":    user,
		})
	}
}

func DeleteUserController(db *sqlx.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		userID := c.Param("id")

		query := "DELETE FROM users WHERE id = $1"
		_, err := db.Exec(query, userID)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "User Data Deleted Successfully",
		})
	}
}

// REGISTRASI
func RegisterController(db *sqlx.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var register UserRegis
		var user UserRegisRespon
		validate := validator.New()

		err := c.Bind(&register) //=>mencocokan data di struct
		//bind =>mengambil data dari input,mengisi var register ,dan mencocokan di struct userreq
		if err != nil {
			return err
		}

		//function validator
		err = validate.Struct(register)
		if err != nil {
			var errormassage []string
			validationErrors := err.(validator.ValidationErrors)
			for _, err := range validationErrors {
				errormassage = append(errormassage, err.Error())
			}
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"message": errormassage,
			})
		}

		//function hasspassword
		password, err := helpers.HashPassword(register.Password)
		if err != nil {
			return err
		}

		query := `
		INSERT INTO users (name, email, age, created_at, password)
		VALUES ( $1, $2, $3, now(), $4)
		RETURNING id, name, email, age, created_at `

		row := db.QueryRowx(query, register.Name, register.Email, register.Age, password) //=>mengambil data yang sama di struct
		err = row.Scan(
			&user.ID,
			&user.Name,
			&user.Email,
			&user.Age,
			&user.CreatedAt,
		)

		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"Message": "Successfully Registered",
			"data":    user,
		})
	}
}

//week 
func BulkDeleteController(db *sqlx.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var request BulkDeleteRequest
		err := c.Bind(&request)

		for _, id := range request.ID {
			query := "DELETE FROM users WHERE id = $1"
			_, err = db.Exec(query, id)
			if err != nil {
				return err
			}
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "successful deletion of some data",
		})
	}
}

// LOGIN
func LoginCompareController(db *sqlx.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var login UserLogin
		var user UserLogRespon
		validate := validator.New()

		err := c.Bind(&login) //=>mencocokan data di struct
		//bind =>mengambil data dari input,mengisi var login ,dan mencocokan di struct userlogin
		if err != nil {
			return err
		}

		//function validator
		err = validate.Struct(login)
		if err != nil {
			var errormassage []string
			validationErrors := err.(validator.ValidationErrors)
			for _, err := range validationErrors {
				errormassage = append(errormassage, err.Error())
			}
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"message": errormassage,
			})
		}

		query := `SELECT id, name, email, age, created_at, updated_at, password FROM users WHERE email = $1 `

		row := db.QueryRowx(query, login.Email) //=>mengambil data yang sama di struct
		err = row.Scan(
			&user.ID,
			&user.Name,
			&user.Email,
			&user.Age,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.Password,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"message": "Email not registered",
				})
			}
			return err
		}

		match, err := helpers.ComparePassword(user.Password, login.Password)

		if err != nil {
			if !match {
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{

					"message": "Passwords do not match",
				})
			}
			return err
		}
		var (
			jwtToken  *jwt.Token
			secretKey = []byte("secret")
		)

		jwtClaims := &Claims{
			ID:    user.ID,
			Email: user.Email,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
			},
		}

		jwtToken = jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)

		token, err := jwtToken.SignedString(secretKey)
		if err != nil {
			return err
		}


		const query2 = `INSERT INTO user_token (user_id, token) VALUES ($1, $2)`
		_ = db.QueryRowx(query2, user.ID, token)

		return c.JSON(http.StatusOK, map[string]interface{}{
			"Message": "Login Successful",
			"token":   token,
			"data":    user,
		})
	}
}

//week
func LogoutController(db *sqlx.DB) echo.HandlerFunc {
		return func(c echo.Context) error {
		var reqToken string
		headerDataToken := c.Request().Header.Get("Authorization")

		splitToken := strings.Split(headerDataToken, "Bearer ")
		if len(splitToken) > 1 {
			reqToken = splitToken[1]
		} else {
			return echo.NewHTTPError(http.StatusUnauthorized)
		}

		query := `DELETE FROM user_token WHERE token = $1`

		_, err := db.Exec(query, reqToken)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.JSON(http.StatusNotFound, map[string]interface{}{
					"message": "Data pengguna tidak ditemukan",
				})
			}
		} 

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "Succesfully Logout",
		})
	}

}
