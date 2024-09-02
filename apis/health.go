package apis

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pocketbase/pocketbase/core"
)

// bindHealthApi registers the health api endpoint.
func bindHealthApi(app core.App, api *gin.RouterGroup) {
	hApi := healthApi{app: app}

	health := api.Group("/health") // изменено с router на api
	health.HEAD("", hApi.healthCheck)
	health.GET("", hApi.healthCheck)
}

type healthApi struct {
	app core.App
}

type healthCheckResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Data    struct {
		CanBackup bool `json:"canBackup"`
	} `json:"data"`
}

// healthCheck returns a 200 OK response if the server is healthy.
func (api *healthApi) healthCheck(c *gin.Context) {
	if c.Request.Method == http.MethodHead {
		c.Status(http.StatusOK)
		return
	}

	resp := new(healthCheckResponse)
	resp.Code = http.StatusOK
	resp.Message = "API is healthy."
	resp.Data.CanBackup = !api.app.Store().Has(core.StoreKeyActiveBackup)

	c.JSON(http.StatusOK, resp)
}
