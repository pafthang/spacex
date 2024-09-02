package apis

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/forms"
	"github.com/pocketbase/pocketbase/models"
	"github.com/pocketbase/pocketbase/tools/search"
)

// bindCollectionApi registers the collection api endpoints and the corresponding handlers.
func bindCollectionApi(app core.App, api *gin.RouterGroup) {
	apiGroup := collectionApi{app: app}

	collections := api.Group("/collections") // Используйте 'api', а не 'router'
	collections.Use(ActivityLogger(app), RequireAdminAuth())
	collections.GET("", apiGroup.list)
	collections.POST("", apiGroup.create)
	collections.GET("/:collection", apiGroup.view)
	collections.PATCH("/:collection", apiGroup.update)
	collections.DELETE("/:collection", apiGroup.delete)
	collections.PUT("/import", apiGroup.bulkImport)
}

type collectionApi struct {
	app core.App
}

func (api *collectionApi) list(c *gin.Context) {
	fieldResolver := search.NewSimpleFieldResolver(
		"id", "created", "updated", "name", "system", "type",
	)

	collections := []*models.Collection{}

	result, err := search.NewProvider(fieldResolver).
		Query(api.app.Dao().CollectionQuery()).
		ParseAndExec(c.Request.URL.RawQuery, &collections)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	event := new(core.CollectionsListEvent)
	event.HttpContext = c
	event.Collections = collections
	event.Result = result

	api.app.OnCollectionsListRequest().Trigger(event, func(e *core.CollectionsListEvent) error {
		if c.Writer.Written() {
			return nil
		}

		c.JSON(http.StatusOK, e.Result)
		return nil
	})
}

func (api *collectionApi) view(c *gin.Context) {
	collection, err := api.app.Dao().FindCollectionByNameOrId(c.Param("collection"))
	if err != nil || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	event := new(core.CollectionViewEvent)
	event.HttpContext = c
	event.Collection = collection

	api.app.OnCollectionViewRequest().Trigger(event, func(e *core.CollectionViewEvent) error {
		if c.Writer.Written() {
			return nil
		}

		c.JSON(http.StatusOK, e.Collection)
		return nil
	})
}

func (api *collectionApi) create(c *gin.Context) {
	collection := &models.Collection{}

	form := forms.NewCollectionUpsert(api.app, collection)

	// load request
	if err := c.ShouldBindJSON(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to load the submitted data due to invalid formatting."})
		return
	}

	event := new(core.CollectionCreateEvent)
	event.HttpContext = c
	event.Collection = collection

	// create the collection
	form.Submit(func(next forms.InterceptorNextFunc[*models.Collection]) forms.InterceptorNextFunc[*models.Collection] {
		return func(m *models.Collection) error {
			event.Collection = m

			return api.app.OnCollectionBeforeCreateRequest().Trigger(event, func(e *core.CollectionCreateEvent) error {
				if err := next(e.Collection); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create the collection."})
					return err
				}

				return api.app.OnCollectionAfterCreateRequest().Trigger(event, func(e *core.CollectionCreateEvent) error {
					if c.Writer.Written() {
						return nil
					}

					c.JSON(http.StatusOK, e.Collection)
					return nil
				})
			})
		}
	})
}

func (api *collectionApi) update(c *gin.Context) {
	collection, err := api.app.Dao().FindCollectionByNameOrId(c.Param("collection"))
	if err != nil || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	form := forms.NewCollectionUpsert(api.app, collection)

	// load request
	if err := c.ShouldBindJSON(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to load the submitted data due to invalid formatting."})
		return
	}

	event := new(core.CollectionUpdateEvent)
	event.HttpContext = c
	event.Collection = collection

	// update the collection
	form.Submit(func(next forms.InterceptorNextFunc[*models.Collection]) forms.InterceptorNextFunc[*models.Collection] {
		return func(m *models.Collection) error {
			event.Collection = m

			return api.app.OnCollectionBeforeUpdateRequest().Trigger(event, func(e *core.CollectionUpdateEvent) error {
				if err := next(e.Collection); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to update the collection."})
					return err
				}

				return api.app.OnCollectionAfterUpdateRequest().Trigger(event, func(e *core.CollectionUpdateEvent) error {
					if c.Writer.Written() {
						return nil
					}

					c.JSON(http.StatusOK, e.Collection)
					return nil
				})
			})
		}
	})
}

func (api *collectionApi) delete(c *gin.Context) {
	collection, err := api.app.Dao().FindCollectionByNameOrId(c.Param("collection"))
	if err != nil || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	event := new(core.CollectionDeleteEvent)
	event.HttpContext = c
	event.Collection = collection

	api.app.OnCollectionBeforeDeleteRequest().Trigger(event, func(e *core.CollectionDeleteEvent) error {
		if err := api.app.Dao().DeleteCollection(e.Collection); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to delete collection due to existing dependency."})
			return err
		}

		return api.app.OnCollectionAfterDeleteRequest().Trigger(event, func(e *core.CollectionDeleteEvent) error {
			if c.Writer.Written() {
				return nil
			}

			c.Status(http.StatusNoContent)
			return nil
		})
	})
}

func (api *collectionApi) bulkImport(c *gin.Context) {
	form := forms.NewCollectionsImport(api.app)

	// load request data
	if err := c.ShouldBindJSON(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to load the submitted data due to invalid formatting."})
		return
	}

	event := new(core.CollectionsImportEvent)
	event.HttpContext = c
	event.Collections = form.Collections

	// import collections
	form.Submit(func(next forms.InterceptorNextFunc[[]*models.Collection]) forms.InterceptorNextFunc[[]*models.Collection] {
		return func(imports []*models.Collection) error {
			event.Collections = imports

			return api.app.OnCollectionsBeforeImportRequest().Trigger(event, func(e *core.CollectionsImportEvent) error {
				if err := next(e.Collections); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to import the submitted collections."})
					return err
				}

				return api.app.OnCollectionsAfterImportRequest().Trigger(event, func(e *core.CollectionsImportEvent) error {
					if c.Writer.Written() {
						return nil
					}

					c.Status(http.StatusNoContent)
					return nil
				})
			})
		}
	})
}
