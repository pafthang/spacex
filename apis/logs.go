package apis

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/models"
	"github.com/pocketbase/pocketbase/tools/search"
)

// bindLogsApi registers the request logs api endpoints.
func bindLogsApi(app core.App, api *gin.RouterGroup) {
	logsApiInstance := logsApi{app: app}

	logs := api.Group("/logs")
	logs.Use(RequireAdminAuth())
	logs.GET("", logsApiInstance.list)
	logs.GET("/stats", logsApiInstance.stats)
	logs.GET("/:id", logsApiInstance.view)
}

type logsApi struct {
	app core.App
}

var logFilterFields = []string{
	"rowid", "id", "created", "updated",
	"level", "message", "data",
	`^data\.[\w\.\:]*\w+$`,
}

func (api *logsApi) list(c *gin.Context) {
	fieldResolver := search.NewSimpleFieldResolver(logFilterFields...)

	result, err := search.NewProvider(fieldResolver).
		Query(api.app.LogsDao().LogQuery()).
		ParseAndExec(c.Request.URL.RawQuery, &[]*models.Log{})

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (api *logsApi) stats(c *gin.Context) {
	fieldResolver := search.NewSimpleFieldResolver(logFilterFields...)

	filter := c.Query(search.FilterQueryParam)

	var expr dbx.Expression
	if filter != "" {
		var err error
		expr, err = search.FilterData(filter).BuildExpr(fieldResolver)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid filter format."})
			return
		}
	}

	stats, err := api.app.LogsDao().LogsStats(expr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to generate logs stats."})
		return
	}

	c.JSON(http.StatusOK, stats)
}

func (api *logsApi) view(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Log ID not found."})
		return
	}

	log, err := api.app.LogsDao().FindLogById(id)
	if err != nil || log == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, log)
}
