package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

var (
// backend_url = fmt.Sprintf("%s://%s:%s", os.Getenv("Mode"), os.Getenv("Backend_Server"), os.Getenv("Backend_Port"))
)

type Page struct {
	Url   string
	Data  interface{}
	Title string
}

func Loginhandler(w http.ResponseWriter, r *http.Request) {

}

func Indexhandler(w http.ResponseWriter, r *http.Request) {

}

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		next.ServeHTTP(w, r)
	})
}

func main() {
	server := fmt.Sprintf("%s:%s", os.Getenv("Server_Address"), os.Getenv("Server_Port"))

	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir(os.Getenv("Assets")))))

	http.HandleFunc("/login", Loginhandler)

	http.Handle("/", AuthMiddleware(http.HandlerFunc(Indexhandler)))

	err := http.ListenAndServeTLS(server, os.Getenv("Certificate"), os.Getenv("Key"), nil)
	if err != nil {
		log.Fatal(err)
	}
}
