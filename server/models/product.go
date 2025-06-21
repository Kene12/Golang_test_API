package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Product struct {
	ID           primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	Name         string             `json:"name" bson:"name"`
	Description  string             `json:"description" bson:"description"`
	Price        float64            `json:"price" bson:"price"`
	Category     string             `json:"category" bson:"category"`
	Stock        int                `json:"stock" bson:"stock"`
	ImageURL     string             `json:"imageUrl" bson:"imageUrl"`
	MerchantID   primitive.ObjectID `json:"merchantId" bson:"merchantId"`
	MerchantName string             `json:"merchantName" bson:"merchantName"`
	IsActive     bool               `json:"isActive" bson:"isActive"`
	CreatedAt    time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt    time.Time          `json:"updatedAt" bson:"updatedAt"`
}

type ProductResponse struct {
	ID           primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	Name         string             `json:"name" bson:"name"`
	Description  string             `json:"description" bson:"description"`
	Price        float64            `json:"price" bson:"price"`
	Category     string             `json:"category" bson:"category"`
	Stock        int                `json:"stock" bson:"stock"`
	ImageURL     string             `json:"imageUrl" bson:"imageUrl"`
	MerchantName string             `json:"merchantName" bson:"merchantName"`
	IsActive     bool               `json:"isActive" bson:"isActive"`
	CreatedAt    time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt    time.Time          `json:"updatedAt" bson:"updatedAt"`
}
