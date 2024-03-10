package security

import (
	"encoding/json"
	"fmt"
	"go-server/server"
	"net/http"
	"time"
	"github.com/dgrijalva/jwt-go"
)

type Admin struct {
	gorm.Model
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

var db *gorm.DB

func registerUser(w http.ResponseWriter, r *http.Request) {
    var user Admin
    json.NewDecoder(r.Body).Decode(&user)

	if r.Method != http.MethodPost {
		http.Error(w, "Not allowed method", http.StatusMethodNotAllowed)
		return
	}

    // Validate user data (username, email, password)
    if err := validateUser(user); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
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

func loginUser(w http.ResponseWriter, r *http.Request) {
	var user server.User
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

/*
// Middleware function to check for valid JWT token
func jwtMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract token from request header
        tokenString := r.Header.Get("Authorization")

        // Verify token
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            return []byte("secret"), nil
        })

        // If token is invalid or missing
        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // Proceed with the request if token is valid
        next.ServeHTTP(w, r)
    })
}

http.Handle("/users", jwtMiddleware(getUsers))






