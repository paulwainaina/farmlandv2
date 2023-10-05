package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/joho/godotenv"
)

var (
	backend_url string
	tpl         *template.Template
)

func init() {
	tpl = template.Must(template.ParseGlob("./templates/*.html"))
}

type Page struct {
	Url   string
	Data  interface{}
	Title string
}

func Loginhandler(w http.ResponseWriter, r *http.Request) {
	page := Page{Url: backend_url}
	err := tpl.ExecuteTemplate(w, "login.html", page)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func Signuphandler(w http.ResponseWriter, r *http.Request) {
	page := Page{Url: backend_url}
	err := tpl.ExecuteTemplate(w, "signup.html", page)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
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
	backend_url = fmt.Sprintf("%s://%s:%s", os.Getenv("Mode"), os.Getenv("Backend_Server"), os.Getenv("Backend_Port"))

	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir(os.Getenv("Assets")))))

	http.HandleFunc("/login", Loginhandler)
	http.HandleFunc("/signup", Signuphandler)

	http.Handle("/", AuthMiddleware(http.HandlerFunc(Indexhandler)))

	err := http.ListenAndServeTLS(server, os.Getenv("Certificate"), os.Getenv("Key"), nil)
	if err != nil {
		log.Fatal(err)
	}
}
