package server

import (
	"encoding/json"
	"fmt"

	"net/http"
	"time"
	"github.com/dgrijalva/jwt-go"
)

// UserCredentials estructura para decodificar el JSON enviado en la solicitud POST
type UserCredentials struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func main() {
	http.HandleFunc("/login", loginHandler) //al ingresar a la dirección / en el servidor ejecutará el index
	http.HandleFunc("/saludo", saludoHandler)
	fmt.Println("El servidor está a la escucha en el servidor 80")
	http.ListenAndServe(":80", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { //se valida si es una solicitud post
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	// Decodificar el JSON del cuerpo de la solicitud
	var credentials UserCredentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Error al decodificar JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Verificar si se proporcionaron usuario y clave
	if credentials.User == "" || credentials.Password == "" {
		http.Error(w, "Usuario y clave son obligatorios", http.StatusBadRequest)
		return
	}

	// Generar el token JWT
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = credentials.User
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["iss"] = "ingesis.uniquindio.edu.co"

	// Firmar el token
	tokenString, err := token.SignedString([]byte("secret")) // Cambia "secret" por tu clave secreta
	if err != nil {
		http.Error(w, "Error al firmar el token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Responder con el token JWT
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, tokenString)
}

func saludoHandler(w http.ResponseWriter, r *http.Request) {
	// Verificar si se proporcionó el parámetro nombre
	nombre := r.URL.Query().Get("nombre")
	if nombre == "" {
		http.Error(w, "Solicitud no válida: El nombre es obligatorio", http.StatusBadRequest)
		return
	}

	// Verificar si se proporcionó el token JWT en el encabezado Authorization
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Token JWT no proporcionado", http.StatusUnauthorized)
		return
	}

	// Verificar si el token JWT es válido y coincide con el nombre proporcionado
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verificar el emisor del token
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("metodo de firma no valido")
		}
		return []byte("secret"), nil // Clave secreta
	})
	if err != nil {
		http.Error(w, "Token JWT inválido (1): "+err.Error(), http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Token JWT inválido (2)", http.StatusUnauthorized)
		return
	}

	// Verificar si el nombre del usuario en el token coincide con el proporcionado en la solicitud
	if user, ok := claims["user"].(string); !ok || user != nombre {
		http.Error(w, "Nombre de usuario en el token no coincide con el proporcionado en la solicitud", http.StatusUnauthorized)
		return
	}

	// Si todo está correcto, responder con un mensaje de saludo
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hola %s", nombre)
}