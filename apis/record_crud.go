package apis

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/daos"
	"github.com/pocketbase/pocketbase/forms"
	"github.com/pocketbase/pocketbase/models"
	"github.com/pocketbase/pocketbase/resolvers"
	"github.com/pocketbase/pocketbase/tools/search"
)

// bindRecordCrudApi registers the record crud api endpoints and
// the corresponding handlers.
func bindRecordCrudApi(app core.App, api *gin.RouterGroup) {
	apiGroup := recordApi{app: app}

	collections := api.Group("/collections/:collection")
	collections.Use(ActivityLogger(app), LoadCollectionContext(app))
	collections.GET("/records", apiGroup.list)
	collections.GET("/records/:id", apiGroup.view)
	collections.POST("/records", apiGroup.create)
	collections.PATCH("/records/:id", apiGroup.update)
	collections.DELETE("/records/:id", apiGroup.delete)
}

type recordApi struct {
	app core.App
}

func (api *recordApi) list(c *gin.Context) {
	value, exists := c.Get(ContextCollectionKey)
	collection, ok := value.(*models.Collection)
	if !exists || !ok || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	requestInfo := RequestInfo(c)

	// forbid users and guests to query special filter/sort fields
	if err := checkForAdminOnlyRuleFields(requestInfo); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	if requestInfo.Admin == nil && collection.ListRule == nil {
		// only admins can access if the rule is nil
		c.JSON(http.StatusForbidden, gin.H{"error": "Only admins can perform this action."})
		return
	}

	fieldsResolver := resolvers.NewRecordFieldResolver(
		api.app.Dao(),
		collection,
		requestInfo,
		// hidden fields are searchable only by admins
		requestInfo.Admin != nil,
	)

	searchProvider := search.NewProvider(fieldsResolver).
		Query(api.app.Dao().RecordQuery(collection))

	if requestInfo.Admin == nil && collection.ListRule != nil {
		searchProvider.AddFilter(search.FilterData(*collection.ListRule))
	}

	records := []*models.Record{}

	result, err := searchProvider.ParseAndExec(c.Request.URL.RawQuery, &records)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	event := new(core.RecordsListEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Records = records
	event.Result = result

	api.app.OnRecordsListRequest().Trigger(event, func(e *core.RecordsListEvent) error {
		if e.HttpContext.Writer.Written() {
			return nil
		}

		if err := EnrichRecords(e.HttpContext, api.app.Dao(), e.Records); err != nil {
			api.app.Logger().Debug("Failed to enrich list records", slog.String("error", err.Error()))
		}

		c.JSON(http.StatusOK, e.Result)
		return nil
	})
}

func (api *recordApi) view(c *gin.Context) {
	value, exists := c.Get(ContextCollectionKey)
	collection, ok := value.(*models.Collection)
	if !exists || !ok || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	recordId := c.Param("id")
	if recordId == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record ID not found."})
		return
	}

	requestInfo := RequestInfo(c)

	if requestInfo.Admin == nil && collection.ViewRule == nil {
		// only admins can access if the rule is nil
		c.JSON(http.StatusForbidden, gin.H{"error": "Only admins can perform this action."})
		return
	}

	ruleFunc := func(q *dbx.SelectQuery) error {
		if requestInfo.Admin == nil && collection.ViewRule != nil && *collection.ViewRule != "" {
			resolver := resolvers.NewRecordFieldResolver(api.app.Dao(), collection, requestInfo, true)
			expr, err := search.FilterData(*collection.ViewRule).BuildExpr(resolver)
			if err != nil {
				return err
			}
			resolver.UpdateQuery(q)
			q.AndWhere(expr)
		}
		return nil
	}

	record, fetchErr := api.app.Dao().FindRecordById(collection.Id, recordId, ruleFunc)
	if fetchErr != nil || record == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fetchErr.Error()})
		return
	}

	event := new(core.RecordViewEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Record = record

	api.app.OnRecordViewRequest().Trigger(event, func(e *core.RecordViewEvent) error {
		if e.HttpContext.Writer.Written() {
			return nil
		}

		if err := EnrichRecord(e.HttpContext, api.app.Dao(), e.Record); err != nil {
			api.app.Logger().Debug(
				"Failed to enrich view record",
				slog.String("id", e.Record.Id),
				slog.String("collectionName", e.Record.Collection().Name),
				slog.String("error", err.Error()),
			)
		}

		c.JSON(http.StatusOK, e.Record)
		return nil
	})
}

func (api *recordApi) create(c *gin.Context) {
	value, exists := c.Get(ContextCollectionKey)
	collection, ok := value.(*models.Collection)
	if !exists || !ok || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	requestInfo := RequestInfo(c)

	if requestInfo.Admin == nil && collection.CreateRule == nil {
		// only admins can access if the rule is nil
		c.JSON(http.StatusForbidden, gin.H{"error": "Only admins can perform this action."})
		return
	}

	hasFullManageAccess := requestInfo.Admin != nil

	// temporary save the record and check it against the create rule
	if requestInfo.Admin == nil && collection.CreateRule != nil {
		testRecord := models.NewRecord(collection)

		// replace modifiers fields so that the resolved value is always
		// available when accessing requestInfo.Data using just the field name
		if requestInfo.HasModifierDataKeys() {
			requestInfo.Data = testRecord.ReplaceModifers(requestInfo.Data)
		}

		testForm := forms.NewRecordUpsert(api.app, testRecord)
		testForm.SetFullManageAccess(true)
		if err := testForm.LoadRequest(c.Request, ""); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to load the submitted data due to invalid formatting."})
			return
		}

		// force unset the verified state to prevent ManageRule misuse
		if !hasFullManageAccess {
			testForm.Verified = false
		}

		createRuleFunc := func(q *dbx.SelectQuery) error {
			if *collection.CreateRule == "" {
				return nil // no create rule to resolve
			}

			resolver := resolvers.NewRecordFieldResolver(api.app.Dao(), collection, requestInfo, true)
			expr, err := search.FilterData(*collection.CreateRule).BuildExpr(resolver)
			if err != nil {
				return err
			}
			resolver.UpdateQuery(q)
			q.AndWhere(expr)
			return nil
		}

		testErr := testForm.DrySubmit(func(txDao *daos.Dao) error {
			foundRecord, err := txDao.FindRecordById(collection.Id, testRecord.Id, createRuleFunc)
			if err != nil {
				return fmt.Errorf("DrySubmit create rule failure: %w", err)
			}
			hasFullManageAccess = hasAuthManageAccess(txDao, foundRecord, requestInfo)
			return nil
		})

		if testErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": testErr.Error()})
			return
		}
	}

	record := models.NewRecord(collection)
	form := forms.NewRecordUpsert(api.app, record)
	form.SetFullManageAccess(hasFullManageAccess)

	// load request
	if err := form.LoadRequest(c.Request, ""); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to load the submitted data due to invalid formatting."})
		return
	}

	event := new(core.RecordCreateEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Record = record
	event.UploadedFiles = form.FilesToUpload()

	// create the record
	form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(m *models.Record) error {
			event.Record = m

			return api.app.OnRecordBeforeCreateRequest().Trigger(event, func(e *core.RecordCreateEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("Failed to create record.", err)
				}

				if err := EnrichRecord(e.HttpContext, api.app.Dao(), e.Record); err != nil {
					api.app.Logger().Debug(
						"Failed to enrich create record",
						slog.String("id", e.Record.Id),
						slog.String("collectionName", e.Record.Collection().Name),
						slog.String("error", err.Error()),
					)
				}

				return api.app.OnRecordAfterCreateRequest().Trigger(event, func(e *core.RecordCreateEvent) error {
					if e.HttpContext.Writer.Written() {
						return nil
					}

					c.JSON(http.StatusOK, e.Record)
					return nil
				})
			})
		}
	})
}

func (api *recordApi) update(c *gin.Context) {
	value, exists := c.Get(ContextCollectionKey)
	collection, ok := value.(*models.Collection)
	if !exists || !ok || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	recordId := c.Param("id")
	if recordId == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record ID not found."})
		return
	}

	requestInfo := RequestInfo(c)

	if requestInfo.Admin == nil && collection.UpdateRule == nil {
		// only admins can access if the rule is nil
		c.JSON(http.StatusForbidden, gin.H{"error": "Only admins can perform this action."})
		return
	}

	// eager fetch the record so that the modifier field values are replaced
	// and available when accessing requestInfo.Data using just the field name
	if requestInfo.HasModifierDataKeys() {
		record, err := api.app.Dao().FindRecordById(collection.Id, recordId)
		if err != nil || record == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		requestInfo.Data = record.ReplaceModifers(requestInfo.Data)
	}

	ruleFunc := func(q *dbx.SelectQuery) error {
		if requestInfo.Admin == nil && collection.UpdateRule != nil && *collection.UpdateRule != "" {
			resolver := resolvers.NewRecordFieldResolver(api.app.Dao(), collection, requestInfo, true)
			expr, err := search.FilterData(*collection.UpdateRule).BuildExpr(resolver)
			if err != nil {
				return err
			}
			resolver.UpdateQuery(q)
			q.AndWhere(expr)
		}
		return nil
	}

	// fetch record
	record, fetchErr := api.app.Dao().FindRecordById(collection.Id, recordId, ruleFunc)
	if fetchErr != nil || record == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fetchErr.Error()})
		return
	}

	form := forms.NewRecordUpsert(api.app, record)
	form.SetFullManageAccess(requestInfo.Admin != nil || hasAuthManageAccess(api.app.Dao(), record, requestInfo))

	// load request
	if err := form.LoadRequest(c.Request, ""); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to load the submitted data due to invalid formatting."})
		return
	}

	event := new(core.RecordUpdateEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Record = record
	event.UploadedFiles = form.FilesToUpload()

	// update the record
	form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(m *models.Record) error {
			event.Record = m

			return api.app.OnRecordBeforeUpdateRequest().Trigger(event, func(e *core.RecordUpdateEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("Failed to update record.", err)
				}

				if err := EnrichRecord(e.HttpContext, api.app.Dao(), e.Record); err != nil {
					api.app.Logger().Debug(
						"Failed to enrich update record",
						slog.String("id", e.Record.Id),
						slog.String("collectionName", e.Record.Collection().Name),
						slog.String("error", err.Error()),
					)
				}

				return api.app.OnRecordAfterUpdateRequest().Trigger(event, func(e *core.RecordUpdateEvent) error {
					if e.HttpContext.Writer.Written() {
						return nil
					}

					c.JSON(http.StatusOK, e.Record)
					return nil
				})
			})
		}
	})
}

func (api *recordApi) delete(c *gin.Context) {
	value, exists := c.Get(ContextCollectionKey)
	collection, ok := value.(*models.Collection)
	if !exists || !ok || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	recordId := c.Param("id")
	if recordId == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record ID not found."})
		return
	}

	requestInfo := RequestInfo(c)

	if requestInfo.Admin == nil && collection.DeleteRule == nil {
		// only admins can access if the rule is nil
		c.JSON(http.StatusForbidden, gin.H{"error": "Only admins can perform this action."})
		return
	}

	ruleFunc := func(q *dbx.SelectQuery) error {
		if requestInfo.Admin == nil && collection.DeleteRule != nil && *collection.DeleteRule != "" {
			resolver := resolvers.NewRecordFieldResolver(api.app.Dao(), collection, requestInfo, true)
			expr, err := search.FilterData(*collection.DeleteRule).BuildExpr(resolver)
			if err != nil {
				return err
			}
			resolver.UpdateQuery(q)
			q.AndWhere(expr)
		}
		return nil
	}

	record, fetchErr := api.app.Dao().FindRecordById(collection.Id, recordId, ruleFunc)
	if fetchErr != nil || record == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fetchErr.Error()})
		return
	}

	event := new(core.RecordDeleteEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Record = record

	api.app.OnRecordBeforeDeleteRequest().Trigger(event, func(e *core.RecordDeleteEvent) error {
		// delete the record
		if err := api.app.Dao().DeleteRecord(e.Record); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to delete record. Make sure that the record is not part of a required relation reference."})
			return err
		}

		return api.app.OnRecordAfterDeleteRequest().Trigger(event, func(e *core.RecordDeleteEvent) error {
			if e.HttpContext.Writer.Written() {
				return nil
			}

			c.Status(http.StatusNoContent)
			return nil
		})
	})
}
