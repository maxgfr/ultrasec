package main

import "github.com/gin-gonic/gin"

func engine() *gin.Engine {
	r := gin.Default()
	r.GET("/me", func(c *gin.Context) {
		c.JSON(200, gin.H{"ip": c.ClientIP()})
	})
	return r
}
