// user_routes.go
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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// contextKey is a custom type for context keys
type userContextKeyType string

const currentUserContextKey userContextKeyType = "currentUser"

func RegisterUserRoutes(r *mux.Router) {
	r.Handle("/Search", IsAuthenticated(SearchUserHandler)).Methods("GET")
	r.Handle("/showUser", IsAuthenticated(ShowMyUserHandler)).Methods("GET")
	r.Handle("/editUser", IsAuthenticated(EditMyUserHandler)).Methods("PATCH")
	r.Handle("/deleteUser", IsAuthenticated(DeleteMyUserHandler)).Methods("DELETE")
}

func IsAuthenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			http.Error(w, "Not authenticated", http.StatusUnauthorized)
			return
		}

		tokenStr := cookie.Value
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		username := claims["id"].(string)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var user models.User
		err = AccountCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
		if err != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		// Add user info to request context
		ctx = context.WithValue(r.Context(), currentUserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func ShowMyUserHandler(w http.ResponseWriter, r *http.Request) {
	// Get current user from context
	user := r.Context().Value(currentUserContextKey).(models.User)

	json.NewEncoder(w).Encode(user)
}

func EditMyUserHandler(w http.ResponseWriter, r *http.Request) {
	// Get current user from context
	currentUser := r.Context().Value(currentUserContextKey).(models.User)

	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	update := bson.M{}
	if body.Username != "" {
		update["username"] = body.Username
	}
	if body.Email != "" {
		update["email"] = body.Email
	}
	if body.Password != "" {
		hashed, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}
		update["password"] = string(hashed)
	}

	// Add updated timestamp
	update["updatedAt"] = time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Update only the current user's data
	result := AccountCollection.FindOneAndUpdate(
		ctx,
		bson.M{"_id": currentUser.ID},
		bson.M{"$set": update},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)

	var updated models.User
	if err := result.Decode(&updated); err != nil {
		http.Error(w, "Can't update user", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User updated successfully",
		"user":    updated,
	})
}

func DeleteMyUserHandler(w http.ResponseWriter, r *http.Request) {
	// Get current user from context
	currentUser := r.Context().Value(currentUserContextKey).(models.User)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Delete only the current user's account
	result, err := AccountCollection.DeleteOne(ctx, bson.M{"_id": currentUser.ID})
	if err != nil || result.DeletedCount == 0 {
		http.Error(w, "Cannot delete user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User deleted successfully",
		"user":    currentUser,
	})
}

func SearchUserHandler(w http.ResponseWriter, r *http.Request) {
	// Get current user from context
	currentUser := r.Context().Value(currentUserContextKey).(models.User)

	var input struct {
		ID       string `json:"_id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	query := bson.M{}

	if input.ID != "" {
		objID, err := primitive.ObjectIDFromHex(input.ID)
		if err == nil {
			query["_id"] = objID
		}
	}
	if input.Username != "" {
		query["username"] = input.Username
	}
	if input.Email != "" {
		query["email"] = input.Email
	}

	if len(query) == 0 {
		http.Error(w, "No search criteria provided", http.StatusBadRequest)
		return
	}

	// Always add current user's ID to ensure they can only search their own data
	query["_id"] = currentUser.ID

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err := AccountCollection.FindOne(ctx, query).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}
