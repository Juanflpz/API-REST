package security

import (
	"encoding/json"
	"fmt"
	"go-rest-api/data"
	"net/http"
	"regexp"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/bcrypt"
	"gorm.io/gorm"
)

func RegisterUser(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	var user data.User
	json.NewDecoder(r.Body).Decode(&user)

	if r.Method != http.MethodPost {
		http.Error(w, "Not allowed method", http.StatusMethodNotAllowed)
		return
	}

	//VALIDATIONS
	if user.Username == "" {
		http.Error(w, "The username must not be empty", http.StatusBadRequest)
		return
	}
	if user.Email == "" {
		http.Error(w, "The email must not be empty", http.StatusBadRequest)
		return
	}
	if !validEmail(user.Email) {
		http.Error(w, "The email must have a valid format", http.StatusBadRequest)
		return
	}

	// Hash the password before storing it in the database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	err = db.Create(&user).Error
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func validEmail(email string) bool {
	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	return re.MatchString(email)
}

func LoginUser(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	var user data.User
	json.NewDecoder(r.Body).Decode(&user)

	if r.Method != http.MethodPost {
		http.Error(w, "Not allowed method", http.StatusMethodNotAllowed)
		return
	}

	err := db.Where("username = ?", user.Username).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		} else {
			http.Error(w, "Error retrieving user", http.StatusInternalServerError)
		}
		return
	}

	// Primero, obtienes el usuario de la base de datos basándote en el username
	var storedUser data.User
	err = db.Where("username = ?", user.Username).First(&storedUser).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		} else {
			http.Error(w, "Error retrieving user", http.StatusInternalServerError)
		}
		return
	}

	// Ahora, user.Password contiene la contraseña ingresada por el usuario
	// storedUser.Password contiene la contraseña hasheada almacenada en la base de datos
	// Compara la contraseña ingresada con la contraseña hasheada almacenada
	if err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	/*
		// Generar el token JWT
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["sub"] = creds.Username
		claims["exp"] = time.Now().Add(time.Hour).Unix() // Token válido por una hora
		claims["iss"] = "ingesis.uniquindio.edu.co" */

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"id":       user.ID,
		"email":    user.Email,
	})
	signedToken, err := token.SignedString([]byte("secret"))
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, signedToken)
}
