package proxy

import "github.com/gin-gonic/gin"

func Configure(r *gin.Engine) {
	gin.SetMode(gin.DebugMode)
	r.SetTrustedProxies([]string{"0.0.0.0/0"})
}
