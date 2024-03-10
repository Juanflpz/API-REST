package security

import (
	"encoding/json"
	"fmt"
	"github.com/golang/bcrypt"
	"go-server/server"
	"net/http"
	"github.com/dgrijalva/jwt-go"
	"regexp"
	"gorm.io/gorm"
)

type Admin struct {
	gorm.Model
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Email     string `json:"email"`
}

var db *gorm.DB

func registerUser(w http.ResponseWriter, r *http.Request) {
    var user Admin
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

func loginUser(w http.ResponseWriter, r *http.Request) {
	var user Admin

    err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Not valid credentials", http.StatusBadRequest)
		return
	}

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

    // Compare passwords (using bcrypt.CompareHashAndPassword)
    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(user.Password)); err != nil {
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
    })
    signedToken, err := token.SignedString([]byte("secret"))
    if err != nil {
        http.Error(w, "Error generating token", http.StatusInternalServerError)
        return
    }

	w.Header().Set("Content-Type", "text/plain")
    fmt.Fprint(w, signedToken)
}






