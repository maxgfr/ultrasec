package main

import (
	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
)

func engine() *gin.Engine {
	r := gin.Default()
	_ = r.SetTrustedProxies([]string{"10.0.0.1"})
	r.Use(secure.New(secure.DefaultConfig()))
	r.GET("/me", func(c *gin.Context) {
		c.JSON(200, gin.H{"ip": c.ClientIP()})
	})
	return r
}
