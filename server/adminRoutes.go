// admin_routes.go
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
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
type adminContextKey string

const adminUserContextKey adminContextKey = "adminUser"

func RegisterAdminRoutes(r *mux.Router) {
	// User Management
	r.Handle("/admin/users", IsAdminMiddleware(GetAllUsersHandler)).Methods("GET")
	r.Handle("/admin/users/{id}", IsAdminMiddleware(GetUserByIDHandler)).Methods("GET")
	r.Handle("/admin/users/{id}", IsAdminMiddleware(UpdateUserByAdminHandler)).Methods("PUT")
	r.Handle("/admin/users/{id}", IsAdminMiddleware(DeleteUserByAdminHandler)).Methods("DELETE")
	r.Handle("/admin/users/{id}/role", IsAdminMiddleware(ChangeUserRoleHandler)).Methods("PATCH")
	r.Handle("/admin/users/{id}/status", IsAdminMiddleware(ToggleUserStatusHandler)).Methods("PATCH")

	// Product Management
	r.Handle("/admin/products", IsAdminMiddleware(GetAllProductsAdminHandler)).Methods("GET")
	r.Handle("/admin/products/{id}", IsAdminMiddleware(GetProductByIDAdminHandler)).Methods("GET")
	r.Handle("/admin/products/{id}", IsAdminMiddleware(UpdateProductByAdminHandler)).Methods("PUT")
	r.Handle("/admin/products/{id}", IsAdminMiddleware(DeleteProductByAdminHandler)).Methods("DELETE")
	r.Handle("/admin/products/{id}/approve", IsAdminMiddleware(ApproveProductHandler)).Methods("PATCH")
	r.Handle("/admin/products/{id}/reject", IsAdminMiddleware(RejectProductHandler)).Methods("PATCH")

	// Statistics & Analytics
	r.Handle("/admin/stats/users", IsAdminMiddleware(GetUserStatsHandler)).Methods("GET")
	r.Handle("/admin/stats/products", IsAdminMiddleware(GetProductStatsHandler)).Methods("GET")
	r.Handle("/admin/stats/overview", IsAdminMiddleware(GetOverviewStatsHandler)).Methods("GET")

	// System Management
	r.Handle("/admin/system/backup", IsAdminMiddleware(BackupSystemHandler)).Methods("POST")
	r.Handle("/admin/system/logs", IsAdminMiddleware(GetSystemLogsHandler)).Methods("GET")
}

// IsAdminMiddleware to check if user is admin
func IsAdminMiddleware(next http.HandlerFunc) http.HandlerFunc {
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
		if err != nil || user.Role != "Admin" {
			http.Error(w, "Access denied. Admins only.", http.StatusForbidden)
			return
		}

		// Add admin user info to request context
		ctx = context.WithValue(r.Context(), adminUserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// ==================== USER MANAGEMENT ====================

// GetAllUsersHandler returns all users with pagination
func GetAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	role := r.URL.Query().Get("role")
	search := r.URL.Query().Get("search")

	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 10
	}

	// Build filter
	filter := bson.M{}
	if role != "" {
		filter["role"] = role
	}
	if search != "" {
		filter["$or"] = []bson.M{
			{"username": bson.M{"$regex": search, "$options": "i"}},
			{"email": bson.M{"$regex": search, "$options": "i"}},
		}
	}

	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64((page - 1) * limit)).
		SetSort(bson.D{{Key: "createdAt", Value: -1}})

	cursor, err := AccountCollection.Find(ctx, filter, opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var users []models.User
	if err := cursor.All(ctx, &users); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get total count
	total, _ := AccountCollection.CountDocuments(ctx, filter)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": users,
		"pagination": map[string]interface{}{
			"page":  page,
			"limit": limit,
			"total": total,
		},
	})
}

// GetUserByIDHandler returns a specific user by ID
func GetUserByIDHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err = AccountCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}

// UpdateUserByAdminHandler allows admin to update any user
func UpdateUserByAdminHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Hash password if provided
	if password, exists := updateData["password"]; exists && password != "" {
		hashed, err := bcrypt.GenerateFromPassword([]byte(password.(string)), 10)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}
		updateData["password"] = string(hashed)
	}

	// Add updated timestamp
	updateData["updatedAt"] = time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := AccountCollection.FindOneAndUpdate(
		ctx,
		bson.M{"_id": objID},
		bson.M{"$set": updateData},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)

	var updatedUser models.User
	if err := result.Decode(&updatedUser); err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User updated successfully",
		"user":    updatedUser,
	})
}

// DeleteUserByAdminHandler allows admin to delete any user
func DeleteUserByAdminHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if user exists
	var user models.User
	err = AccountCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Prevent admin from deleting themselves
	adminUser := r.Context().Value(adminUserContextKey).(models.User)
	if user.ID == adminUser.ID {
		http.Error(w, "Cannot delete your own account", http.StatusForbidden)
		return
	}

	result, err := AccountCollection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil || result.DeletedCount == 0 {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User deleted successfully",
		"user":    user,
	})
}

// ChangeUserRoleHandler changes user role
func ChangeUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate role
	validRoles := []string{"User", "Merchant", "Admin"}
	isValidRole := false
	for _, role := range validRoles {
		if body.Role == role {
			isValidRole = true
			break
		}
	}
	if !isValidRole {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := AccountCollection.FindOneAndUpdate(
		ctx,
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{"role": body.Role, "updatedAt": time.Now()}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)

	var updatedUser models.User
	if err := result.Decode(&updatedUser); err != nil {
		http.Error(w, "Failed to update user role", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User role updated successfully",
		"user":    updatedUser,
	})
}

// ToggleUserStatusHandler toggles user active status
func ToggleUserStatusHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get current user status
	var user models.User
	err = AccountCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Toggle status (assuming we add an IsActive field to User model)
	// For now, we'll use a simple approach
	newStatus := !user.IsActive // This would need IsActive field in User model

	result := AccountCollection.FindOneAndUpdate(
		ctx,
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{"isActive": newStatus, "updatedAt": time.Now()}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)

	var updatedUser models.User
	if err := result.Decode(&updatedUser); err != nil {
		http.Error(w, "Failed to update user status", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User status updated successfully",
		"user":    updatedUser,
	})
}

// ==================== PRODUCT MANAGEMENT ====================

// GetAllProductsAdminHandler returns all products (including inactive)
func GetAllProductsAdminHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	status := r.URL.Query().Get("status")
	category := r.URL.Query().Get("category")

	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 10
	}

	// Build filter
	filter := bson.M{}
	switch status {
	case "active":
		filter["isActive"] = true
	case "inactive":
		filter["isActive"] = false
	}
	if category != "" {
		filter["category"] = category
	}

	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64((page - 1) * limit)).
		SetSort(bson.D{{Key: "createdAt", Value: -1}})

	cursor, err := ProductCollection.Find(ctx, filter, opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var products []models.Product
	if err := cursor.All(ctx, &products); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get total count
	total, _ := ProductCollection.CountDocuments(ctx, filter)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"products": products,
		"pagination": map[string]interface{}{
			"page":  page,
			"limit": limit,
			"total": total,
		},
	})
}

// GetProductByIDAdminHandler returns a specific product by ID
func GetProductByIDAdminHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	productID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(productID)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var product models.Product
	err = ProductCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&product)
	if err != nil {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(product)
}

// UpdateProductByAdminHandler allows admin to update any product
func UpdateProductByAdminHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	productID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(productID)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Add updated timestamp
	updateData["updatedAt"] = time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := ProductCollection.FindOneAndUpdate(
		ctx,
		bson.M{"_id": objID},
		bson.M{"$set": updateData},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)

	var updatedProduct models.Product
	if err := result.Decode(&updatedProduct); err != nil {
		http.Error(w, "Failed to update product", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Product updated successfully",
		"product": updatedProduct,
	})
}

// DeleteProductByAdminHandler allows admin to permanently delete any product
func DeleteProductByAdminHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	productID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(productID)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get product before deletion
	var product models.Product
	err = ProductCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&product)
	if err != nil {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	// Permanently delete
	result, err := ProductCollection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil || result.DeletedCount == 0 {
		http.Error(w, "Failed to delete product", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Product permanently deleted",
		"product": product,
	})
}

// ApproveProductHandler approves a product
func ApproveProductHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	productID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(productID)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := ProductCollection.FindOneAndUpdate(
		ctx,
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{"isActive": true, "updatedAt": time.Now()}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)

	var updatedProduct models.Product
	if err := result.Decode(&updatedProduct); err != nil {
		http.Error(w, "Failed to approve product", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Product approved successfully",
		"product": updatedProduct,
	})
}

// RejectProductHandler rejects a product
func RejectProductHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	productID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(productID)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := ProductCollection.FindOneAndUpdate(
		ctx,
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{"isActive": false, "updatedAt": time.Now()}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)

	var updatedProduct models.Product
	if err := result.Decode(&updatedProduct); err != nil {
		http.Error(w, "Failed to reject product", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Product rejected successfully",
		"product": updatedProduct,
	})
}

// ==================== STATISTICS & ANALYTICS ====================

// GetUserStatsHandler returns user statistics
func GetUserStatsHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get counts by role
	pipeline := []bson.M{
		{
			"$group": bson.M{
				"_id":   "$role",
				"count": bson.M{"$sum": 1},
			},
		},
	}

	cursor, err := AccountCollection.Aggregate(ctx, pipeline)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get total users
	totalUsers, _ := AccountCollection.CountDocuments(ctx, bson.M{})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalUsers": totalUsers,
		"byRole":     results,
	})
}

// GetProductStatsHandler returns product statistics
func GetProductStatsHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get counts by category
	pipeline := []bson.M{
		{
			"$group": bson.M{
				"_id":   "$category",
				"count": bson.M{"$sum": 1},
			},
		},
	}

	cursor, err := ProductCollection.Aggregate(ctx, pipeline)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get total products
	totalProducts, _ := ProductCollection.CountDocuments(ctx, bson.M{})
	activeProducts, _ := ProductCollection.CountDocuments(ctx, bson.M{"isActive": true})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalProducts":  totalProducts,
		"activeProducts": activeProducts,
		"byCategory":     results,
	})
}

// GetOverviewStatsHandler returns overview statistics
func GetOverviewStatsHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get various counts
	totalUsers, _ := AccountCollection.CountDocuments(ctx, bson.M{})
	totalProducts, _ := ProductCollection.CountDocuments(ctx, bson.M{})
	activeProducts, _ := ProductCollection.CountDocuments(ctx, bson.M{"isActive": true})

	// Get recent activity (last 7 days)
	weekAgo := time.Now().AddDate(0, 0, -7)
	recentUsers, _ := AccountCollection.CountDocuments(ctx, bson.M{
		"createdAt": bson.M{"$gte": weekAgo},
	})
	recentProducts, _ := ProductCollection.CountDocuments(ctx, bson.M{
		"createdAt": bson.M{"$gte": weekAgo},
	})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"overview": map[string]interface{}{
			"totalUsers":     totalUsers,
			"totalProducts":  totalProducts,
			"activeProducts": activeProducts,
		},
		"recentActivity": map[string]interface{}{
			"newUsers":    recentUsers,
			"newProducts": recentProducts,
			"period":      "7 days",
		},
	})
}

// ==================== SYSTEM MANAGEMENT ====================

// BackupSystemHandler creates a system backup
func BackupSystemHandler(w http.ResponseWriter, r *http.Request) {
	// This would typically involve creating database dumps
	// For now, we'll return a placeholder response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "System backup initiated",
		"timestamp": time.Now(),
		"status":    "in_progress",
	})
}

// GetSystemLogsHandler returns system logs
func GetSystemLogsHandler(w http.ResponseWriter, r *http.Request) {
	// This would typically involve reading from log files
	// For now, we'll return a placeholder response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "System logs retrieved",
		"logs": []map[string]interface{}{
			{
				"timestamp": time.Now(),
				"level":     "INFO",
				"message":   "Admin routes accessed",
			},
		},
	})
}
