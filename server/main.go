package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize database
	InitDB()

	r := mux.NewRouter()

	// Register routes
	RegisterAuthRoutes(r)
	RegisterUserRoutes(r)
	RegisterProductRoutes(r)
	RegisterAdminRoutes(r)

	// Start server
	log.Println("Server running on http://localhost:5000")
	http.ListenAndServe(":5000", r)
}
