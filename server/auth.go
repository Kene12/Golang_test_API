package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/Kene12/Golang_test_API/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

func RegisterAuthRoutes(r *mux.Router) {
	InitDB()

	r.HandleFunc("/auth/registerUser", RegisterHandler("User")).Methods("POST")
	r.HandleFunc("/auth/registerMerchant", RegisterHandler("Merchant")).Methods("POST")
	r.HandleFunc("/auth/registerAdmin", RegisterHandler("Admin")).Methods("POST")
	r.HandleFunc("/auth/login", LoginHandler).Methods("POST")
	r.HandleFunc("/auth/logout", LogoutHandler).Methods("POST")
}

func RegisterHandler(role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		json.NewDecoder(r.Body).Decode(&user)

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
		user.Password = string(hashedPassword)
		user.Role = role
		user.ID = primitive.NewObjectID()
		user.IsActive = true
		user.CreatedAt = time.Now()
		user.UpdatedAt = time.Now()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := AccountCollection.InsertOne(ctx, user)
		if err != nil {
			http.Error(w, "Failed to register", 500)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"message": role + " registered successfully"})
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Iden     string `json:"iden"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&creds)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err := AccountCollection.FindOne(ctx, map[string]interface{}{
		"$or": []map[string]string{
			{"email": creds.Iden},
			{"username": creds.Iden},
		},
	}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", 400)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", 400)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  user.Username,
		"exp": time.Now().Add(3 * time.Hour).Unix(),
	})

	tokenString, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Path:     "/",
		MaxAge:   60 * 60,
		HttpOnly: true,
	})

	json.NewEncoder(w).Encode(map[string]string{"message": "Login successful"})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}
