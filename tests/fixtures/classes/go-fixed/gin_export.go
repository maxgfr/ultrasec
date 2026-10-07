package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func exportRoutes(r *gin.Engine, db *gorm.DB) {
	r.GET("/export/orders", func(c *gin.Context) {
		var orders []Order
		db.Order("id").Limit(500).Find(&orders)
		c.JSON(200, orders)
	})
}
