package server

import (
	//"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Email     string `json:"email"`
}

var db *gorm.DB

// var db1 *sql.DB //hold the database connection
func main() {
	//host := os.Getenv("DATABASE")
	//host := "localhost"
	var DSN = "host= localhost user=philly password=root1234 dbname=clients port=5432"
	var error error
	db, error = gorm.Open(postgres.Open(DSN), &gorm.Config{})
	if error != nil {
		log.Fatal(error)
	} else {
		log.Println("BD CONECTADA")
	}

	http.HandleFunc("/users", getUsers)
	http.HandleFunc("/users/create", createUser)
	http.HandleFunc("/users/update/{id}", updateUser)
	http.HandleFunc("/users/delete/{id}", deleteUser)
	http.HandleFunc("/users/{id}", getUser)

	fmt.Println("Server listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	//gets the id value from the route with mux
	id, err := strconv.Atoi(mux.Vars(r)["id"]) //turns the value into an int with strconv.Atoi
	if err != nil {
		http.Error(w, "Not valid ID", http.StatusBadRequest)
		return
	}

	if r.Method != "PATCH" {
		http.Error(w, "Not allowed method", http.StatusMethodNotAllowed)
		return
	}

	//dudo acá-------------------------------------------------------------------------
	var user User
	err = json.NewDecoder(r.Body).Decode(&user) //attempts to decode the request body into the user struct
	if err != nil {
		http.Error(w, "Not valid REQUEST", http.StatusBadRequest)
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
	//updates the user in the database using the Updates function from GORM
	err = db.Model(&User{}).Where("id = ?", id).Updates(user).Error
	if err == gorm.ErrRecordNotFound {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error()+"hola prueba", http.StatusInternalServerError)
		return
	}

	//Gets the updated user
	updatedUser := User{}
	err = db.First(&updatedUser, id).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//WRITES THE RESPONSEWRITER WITH THE USER DATA IN JSON FORMAT
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)

	//CONSOLE COMMANDS:
	//curl -X PATCH -H "Content-Type: application/json" -d '{ "username": "nuevo_nombre_usuario", "email": "nuevo_correo@ejemplo.com" }' http://localhost:8080/users/update/{id}
}

func validEmail(email string) bool {
	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	return re.MatchString(email)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	//gets the id value from the route with mux
	id, err := strconv.Atoi(mux.Vars(r)["id"]) //turns the value into an int with strconv.Atoi
	if err != nil {
		http.Error(w, "Not valid ID", http.StatusBadRequest)
		return
	}

	user := User{}
	err = db.First(&user, id).Error //obtains the user by its id in the database using the First function from GORM
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//WRITES THE RESPONSEWRITER WITH THE USER DATA IN JSON FORMAT
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)

	//CONSOLE COMMANDS:
	//http://localhost:8080/users/{id} OR curl -X GET http://localhost:8080/users/{user}
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	//gets the id value from the route with mux
	id, err := strconv.Atoi(mux.Vars(r)["id"]) //turns the value into an int with strconv.Atoi
	if err != nil {
		http.Error(w, "Not valid id", http.StatusBadRequest)
		return
	}

	if r.Method != "DELETE" {
		http.Error(w, "Not allowed method", http.StatusMethodNotAllowed)
		return
	}

	err = db.Delete(&User{}, id).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Deleted user from the DB"))

	//CONSOLE COMMANDS:
	//curl -X DELETE http://localhost:8080/users/delete/{id}
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Raw("SELECT id, username, email, created_at FROM clients").Rows() //executes the query
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users := []User{} //empty list
	for rows.Next() { //iterates from the query
		var user User //gets every user in the list
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.CreatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user) //adds every user in the list
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(users) //writes the list to the responseWriter

	//console commands:
	//curl http://localhost:8080/users
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user) //attempts to decode the request body into the user struct

	if r.Method != "POST" {
		http.Error(w, "Not allowed method", http.StatusMethodNotAllowed)
		return
	}

	err := db.Exec("INSERT INTO users (id, username, password, email) VALUES ($1, $2, $3, $4)", user.ID, user.Username, user.Password, user.Email).Error
	if err != nil {
		pqErr, ok := err.(*pq.Error) //checks if the username or email already exists in the db
		if ok && pqErr.Code.Name() == "unique_violation" {
			http.Error(w, "Username or Email already exists", http.StatusConflict)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError) //for other conflicts that may happen
		}
		return
	}
	w.WriteHeader(http.StatusCreated) //successful

	//console commands:
	//#curl -X POST http://localhost:8080/users/create -H "Content-Type: application/json" -d '{"username": "johndoe", "email": "johndoe@example.com", "password": "your_password"}'
}
