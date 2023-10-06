package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"example.com/sessions"
	"example.com/users"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	userSessions *sessions.SessionsManager
	systemUsers  *users.Users
	db           *mongo.Database
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", fmt.Sprintf("%s://%s:%s", os.Getenv("Mode"), os.Getenv("Frontend_Server"), os.Getenv("Frontend_Port")))
		if r.Method == http.MethodOptions {
			w.Header().Add("Access-Control-Allow-Headers", "POST,GET,PUT,DELETE")
			w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusOK)
			return
		}
		if !strings.EqualFold(r.URL.Path, "/forgot") && !strings.EqualFold(r.URL.Path, "/confirm") && !strings.EqualFold(r.URL.Path, "/request") && !strings.EqualFold(r.URL.Path, "/signin") && !strings.EqualFold(r.URL.Path, "/signup") && !(strings.EqualFold(r.URL.Path, "/users") && r.Method == http.MethodPost) {
			session, err := r.Cookie("session")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(struct{}{})
				return
			}
			username, err := r.Cookie("username")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(struct{}{})
				return
			}
			found, _ := userSessions.GetSession(username.Value, session.Value)
			if !found {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(struct{}{})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	userSessions = sessions.NewSessionsManager()
	go userSessions.ManageSession()

	clientOptions := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%s", os.Getenv("Mongo_Host"), os.Getenv("Mongo_Port")))
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.TODO())

	db = client.Database(os.Getenv("Database"))

	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir(os.Getenv("Assets")))))

	systemUsers = users.NewUsers(userSessions, db)
	http.Handle("/users", AuthMiddleware(http.HandlerFunc(systemUsers.ServeHTTP)))
	http.Handle("/signin", AuthMiddleware(http.HandlerFunc(systemUsers.ServeHTTP)))
	http.Handle("/password", AuthMiddleware(http.HandlerFunc(systemUsers.ServeHTTP)))
	http.Handle("/confirm", AuthMiddleware(http.HandlerFunc(systemUsers.ServeHTTP)))
	http.Handle("/request", AuthMiddleware(http.HandlerFunc(systemUsers.ServeHTTP)))
	http.Handle("/forgot", AuthMiddleware(http.HandlerFunc(systemUsers.ServeHTTP)))

	server := fmt.Sprintf("%s:%s", os.Getenv("Server_Address"), os.Getenv("Server_Port"))
	err = http.ListenAndServeTLS(server, os.Getenv("Certificate"), os.Getenv("Key"), nil)
	if err != nil {
		log.Fatal(err)
	}
}
