package users

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"example.com/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Active   bool   `bson:"Active"`
	Premium  bool   `bson:"Premium"`
	Name     string `bson:"Name"`
	Passport string `bson:"Passport"`
	Password string `bson:"Password"`
	Email    string `bson:"Email"`
	Code     string `bson:"Code"`
}

type Users struct {
	systemUsers []*User
	authSession *sessions.SessionsManager
	db          *mongo.Database
}

var (
	userCollection = "user"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func NewUsers(auth *sessions.SessionsManager, db *mongo.Database) *Users {
	users := make([]*User, 0)
	col := db.Collection(userCollection)
	result, err := col.Find(context.TODO(), bson.M{})
	if err != nil {
		log.Fatal(err.Error())
	} else {
		if err = result.All(context.TODO(), &users); err != nil {
			log.Fatal("error reading users from database" + err.Error())
		}
	}
	return &Users{systemUsers: users, authSession: auth, db: db}
}

func (users *Users) AddUser(usr User) (*User, error) {
	for _, m := range users.systemUsers {
		if strings.EqualFold(m.Email, usr.Email) {
			return &User{}, fmt.Errorf("a user with the same email exists %s", m.Email)
		}
	}
	h, err := HashPassword(usr.Password)
	if err != nil {
		return &User{}, fmt.Errorf("internal server error hashing")
	}
	usr.Password = h
	col := users.db.Collection(userCollection)
	_, err = col.InsertOne(context.TODO(), usr)
	if err != nil {
		return &User{}, err
	}
	users.systemUsers = append(users.systemUsers, &usr)
	return &usr, nil
}

func (users *Users) GetUserEmail(email string) (*User, error) {
	for _, m := range users.systemUsers {
		if strings.EqualFold(m.Email, email) {
			return m, nil
		}
	}
	return &User{}, fmt.Errorf("user with email %s not found", email)
}

func (users *Users) DeleteUserEmail(email string) (*User, error) {
	for i, m := range users.systemUsers {
		if m.Email == email {
			if len(m.Passport) != 0 {
				os.Remove(os.Getenv("Assets") + "/" + m.Passport)
			}
			col := users.db.Collection(userCollection)
			_, err := col.DeleteOne(context.TODO(), bson.M{"Email": email})
			if err != nil {
				return &User{}, err
			}
			users.systemUsers = append(users.systemUsers[:i], users.systemUsers[i+1:]...)
			return m, nil
		}
	}
	return &User{}, fmt.Errorf("user with email %s not found", email)
}

func (users *Users) UpdateUser(usr User) (*User, error) {
	for _, m := range users.systemUsers {
		if strings.EqualFold(m.Email, usr.Email) {
			if len(m.Passport) != 0 && !strings.EqualFold(m.Passport, usr.Passport) {
				os.Remove(os.Getenv("Assets") + m.Passport)
			}
			col := users.db.Collection(userCollection)
			_, err := col.UpdateOne(context.TODO(), bson.M{"Email": usr.Email},
				bson.M{"$set": bson.M{
					"Name":     usr.Name,
					"Active":   usr.Active,
					"Passport": usr.Passport,
				}})
			if err != nil {
				return &User{}, err
			}
			m.Name = usr.Name
			m.Active = usr.Active
			m.Passport = usr.Passport
			return m, nil
		}
	}
	return &User{}, fmt.Errorf("user with email %s not found", usr.Email)
}

func (users *Users) ChangePassword(email, code, current, new string) error {
	for _, u := range users.systemUsers {
		if strings.EqualFold(u.Email, email) {
			if strings.EqualFold(code, u.Code) {
				return fmt.Errorf("wrong code provided")
			}
			if CheckPasswordHash(current, u.Password) {
				return fmt.Errorf("current password does not match")
			}
			password, err := HashPassword(new)
			if err != nil {
				return fmt.Errorf("internal server error hashing")
			}
			col := users.db.Collection(userCollection)
			_, err = col.UpdateOne(context.TODO(), bson.M{"Email": u.Email},
				bson.M{"$set": bson.M{
					"Password": password,
				}})
			if err != nil {
				return fmt.Errorf("internal server error")
			}
			u.Password = password
			return nil
		}
	}
	return fmt.Errorf("user %s does not exist", email)
}

func (users *Users) LoginUser(usr User) (*User, error) {
	for _, m := range users.systemUsers {
		if strings.EqualFold(m.Email, usr.Email) {
			if !m.Active {
				return &User{}, fmt.Errorf("user is inactive")
			}
			if !CheckPasswordHash(usr.Password, m.Password) {
				return &User{}, fmt.Errorf("wrong credentials")
			}
			return m, nil
		}
	}
	return &User{}, fmt.Errorf("wrong credentials %s", usr.Email)
}

func (users *Users) ActivateUser(email, code string) (*User, error) {
	for _, m := range users.systemUsers {
		if strings.EqualFold(m.Email, email) {
			if strings.EqualFold(m.Code, code) {
				m.Active = true
				return m, nil
			}
			return &User{}, fmt.Errorf("invalid code entered")
		}
	}
	return &User{}, fmt.Errorf("user does not exist")
}

func (users *Users) ResendUserCode(email string) error {
	for _, m := range users.systemUsers {
		if strings.EqualFold(m.Email, email) {
			return nil
		}
	}
	return fmt.Errorf("user does not exist")
}

func (users *Users) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/password" {
		var user struct {
			Email   string
			Current string
			New     string
			Code    string
		}
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err = users.ChangePassword(user.Email, user.Code, user.Current, user.New)
		if err != nil {
			json.NewEncoder(w).Encode(struct{ Error string }{Error: err.Error()})
			return
		}
		json.NewEncoder(w).Encode("")
		return
	} else if r.URL.Path == "/signin" {
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		u, err := users.LoginUser(user)
		if err != nil {
			json.NewEncoder(w).Encode(struct{ Error string }{Error: err.Error()})
			return
		}
		sess := users.authSession.CreateNewSession(u.Email)
		if sess == nil {
			json.NewEncoder(w).Encode(struct{ Error string }{Error: "internal error sessions"})
			return
		}
		http.SetCookie(w, &sess.Cookie)
		http.SetCookie(w, &http.Cookie{Name: "username", Value: u.Email})
		json.NewEncoder(w).Encode(u)
		return
	} else if r.URL.Path == "/confirm" {
		var user struct {
			Email string
			Code  string
		}
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		u, err := users.ActivateUser(user.Email, user.Code)
		if err != nil {
			json.NewEncoder(w).Encode(struct{ Error string }{Error: err.Error()})
			return
		}
		json.NewEncoder(w).Encode(u)
		return
	} else if r.URL.Path == "/request" {
		var user struct {
			Email string
		}
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err = users.ResendUserCode(user.Email)
		if err != nil {
			json.NewEncoder(w).Encode(struct{ Error string }{Error: err.Error()})
			return
		}
		return
	}
	if r.URL.Path == "/users" {
		switch r.Method {
		case http.MethodGet:
			{
				var filter struct {
					Email string
				}
				err := json.NewDecoder(r.Body).Decode(&filter)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if len(filter.Email) == 0 {
					json.NewEncoder(w).Encode(users.systemUsers)
				}
				u, err := users.GetUserEmail(filter.Email)
				if err != nil {
					json.NewEncoder(w).Encode(struct{ Error string }{Error: err.Error()})
					return
				}
				json.NewEncoder(w).Encode(u)
				return
			}
		case http.MethodPost:
			{
				var user User
				err := json.NewDecoder(r.Body).Decode(&user)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				u, err := users.AddUser(user)
				if err != nil {
					json.NewEncoder(w).Encode(struct{ Error string }{Error: err.Error()})
					return
				}
				json.NewEncoder(w).Encode(u)
			}
		case http.MethodPut:
			{
				var user User
				err := json.NewDecoder(r.Body).Decode(&user)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				u, err := users.UpdateUser(user)
				if err != nil {
					json.NewEncoder(w).Encode(struct{ Error string }{Error: err.Error()})
					return
				}
				json.NewEncoder(w).Encode(u)
			}
		case http.MethodDelete:
			{
				var user User
				err := json.NewDecoder(r.Body).Decode(&user)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				u, err := users.DeleteUserEmail(user.Email)
				if err != nil {
					json.NewEncoder(w).Encode(struct{ Error string }{Error: err.Error()})
					return
				}
				json.NewEncoder(w).Encode(u)
			}
		default:
			{
				w.WriteHeader(http.StatusNotImplemented)
				w.Write([]byte("method not implemented"))
				return
			}
		}
	}
}
