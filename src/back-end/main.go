package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"example.com/sessions"
	"github.com/joho/godotenv"
)

var (
	userSessions *sessions.SessionsManager
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
		if !strings.EqualFold(r.URL.Path, "/login") || !strings.EqualFold(r.URL.Path, "/signup") {
			session, err := r.Cookie("session")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			username, err := r.Cookie("username")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			found, _ := userSessions.GetSession(username.Value, session.Value)
			if !found {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	server := fmt.Sprintf("%s:%s", os.Getenv("Server_Address"), os.Getenv("Server_Port"))
	userSessions = sessions.NewSessionsManager()

	go userSessions.ManageSession()

	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir(os.Getenv("Assets")))))

	err := http.ListenAndServeTLS(server, os.Getenv("Certificate"), os.Getenv("Key"), nil)
	if err != nil {
		log.Fatal(err)
	}
}
