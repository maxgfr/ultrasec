package proxy

import "github.com/gin-gonic/gin"

func Configure(r *gin.Engine) {
	gin.SetMode(gin.ReleaseMode)
	r.SetTrustedProxies([]string{"10.0.0.1"})
}
