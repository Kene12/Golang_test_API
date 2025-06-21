// product_routes.go
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
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const userContextKey contextKey = "user"

func RegisterProductRoutes(r *mux.Router) {
	r.HandleFunc("/products", GetAllProductsHandler).Methods("GET")
	r.HandleFunc("/products/search", SearchProductsHandler).Methods("GET")
	r.HandleFunc("/products/category/{category}", GetProductsByCategoryHandler).Methods("GET")
	r.Handle("/products", IsMerchant(CreateProductHandler)).Methods("POST")
	r.Handle("/products/{id}", IsMerchant(UpdateProductHandler)).Methods("PUT")
	r.Handle("/products/{id}", IsMerchant(DeleteProductHandler)).Methods("DELETE")
	r.HandleFunc("/products/{id}", GetProductByIDHandler).Methods("GET")
}

// IsMerchant middleware to check if user is a merchant
func IsMerchant(next http.HandlerFunc) http.HandlerFunc {
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
		if err != nil || (user.Role != "Merchant" && user.Role != "Admin") {
			http.Error(w, "Access denied. Merchants and Admins only.", http.StatusForbidden)
			return
		}

		// Add user info to request context
		ctx = context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetAllProductsHandler returns all active products
func GetAllProductsHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get query parameters for pagination
	page := r.URL.Query().Get("page")
	limit := r.URL.Query().Get("limit")

	// Default values
	pageNum := int64(1)
	limitNum := int64(10)

	if page != "" {
		if p, err := strconv.ParseInt(page, 10, 64); err == nil && p > 0 {
			pageNum = p
		}
	}
	if limit != "" {
		if l, err := strconv.ParseInt(limit, 10, 64); err == nil && l > 0 {
			limitNum = l
		}
	}

	opts := options.Find().
		SetLimit(limitNum).
		SetSkip((pageNum - 1) * limitNum).
		SetSort(bson.D{{Key: "createdAt", Value: -1}})

	cursor, err := ProductCollection.Find(ctx, bson.M{"isActive": true}, opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var products []models.ProductResponse
	if err := cursor.All(ctx, &products); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"products": products,
		"page":     pageNum,
		"limit":    limitNum,
	})
}

// SearchProductsHandler searches products by name or description
func SearchProductsHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Search query is required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	searchFilter := bson.M{
		"$and": []bson.M{
			{"isActive": true},
			{
				"$or": []bson.M{
					{"name": bson.M{"$regex": query, "$options": "i"}},
					{"description": bson.M{"$regex": query, "$options": "i"}},
				},
			},
		},
	}

	cursor, err := ProductCollection.Find(ctx, searchFilter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var products []models.ProductResponse
	if err := cursor.All(ctx, &products); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(products)
}

// GetProductsByCategoryHandler returns products by category
func GetProductsByCategoryHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	category := vars["category"]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := ProductCollection.Find(ctx, bson.M{
		"category": category,
		"isActive": true,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var products []models.ProductResponse
	if err := cursor.All(ctx, &products); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(products)
}

// CreateProductHandler creates a new product
func CreateProductHandler(w http.ResponseWriter, r *http.Request) {
	var product models.Product
	if err := json.NewDecoder(r.Body).Decode(&product); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if product.Name == "" || product.Price <= 0 || product.Stock < 0 {
		http.Error(w, "Name, price, and stock are required fields", http.StatusBadRequest)
		return
	}

	// Get merchant info from context
	user := r.Context().Value(userContextKey).(models.User)

	// Set product details
	product.ID = primitive.NewObjectID()
	product.MerchantID = user.ID
	product.MerchantName = user.Username
	product.IsActive = true
	product.CreatedAt = time.Now()
	product.UpdatedAt = time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := ProductCollection.InsertOne(ctx, product)
	if err != nil {
		http.Error(w, "Failed to create product", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Product created successfully",
		"product": product,
	})
}

// UpdateProductHandler updates an existing product
func UpdateProductHandler(w http.ResponseWriter, r *http.Request) {
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

	// Get merchant info from context
	user := r.Context().Value(userContextKey).(models.User)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if product exists and belongs to the merchant
	var existingProduct models.Product
	err = ProductCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&existingProduct)
	if err != nil {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	// Only allow merchants to update their own products (unless admin)
	if user.Role != "Admin" && existingProduct.MerchantID != user.ID {
		http.Error(w, "Access denied. You can only update your own products.", http.StatusForbidden)
		return
	}

	// Add updated timestamp
	updateData["updatedAt"] = time.Now()

	// Remove fields that shouldn't be updated
	delete(updateData, "_id")
	delete(updateData, "merchantId")
	delete(updateData, "merchantName")
	delete(updateData, "createdAt")

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

// DeleteProductHandler deletes a product (soft delete)
func DeleteProductHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	productID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(productID)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	// Get merchant info from context
	user := r.Context().Value(userContextKey).(models.User)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if product exists and belongs to the merchant
	var existingProduct models.Product
	err = ProductCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&existingProduct)
	if err != nil {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	// Only allow merchants to delete their own products (unless admin)
	if user.Role != "Admin" && existingProduct.MerchantID != user.ID {
		http.Error(w, "Access denied. You can only delete your own products.", http.StatusForbidden)
		return
	}

	// Soft delete by setting isActive to false
	result := ProductCollection.FindOneAndUpdate(
		ctx,
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{"isActive": false, "updatedAt": time.Now()}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)

	var deletedProduct models.Product
	if err := result.Decode(&deletedProduct); err != nil {
		http.Error(w, "Failed to delete product", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Product deleted successfully",
		"product": deletedProduct,
	})
}

// GetProductByIDHandler returns a specific product by ID
func GetProductByIDHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	productID := vars["id"]

	objID, err := primitive.ObjectIDFromHex(productID)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var product models.ProductResponse
	err = ProductCollection.FindOne(ctx, bson.M{"_id": objID, "isActive": true}).Decode(&product)
	if err != nil {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(product)
}
