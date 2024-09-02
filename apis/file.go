package apis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/models"
	"github.com/pocketbase/pocketbase/models/schema"
	"github.com/pocketbase/pocketbase/tokens"
	"github.com/pocketbase/pocketbase/tools/filesystem"
	"github.com/pocketbase/pocketbase/tools/list"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/spf13/cast"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"
)

var imageContentTypes = []string{"image/png", "image/jpg", "image/jpeg", "image/gif"}
var defaultThumbSizes = []string{"100x100"}

// bindFileApi registers the file api endpoints and the corresponding handlers.
func bindFileApi(app core.App, r *gin.RouterGroup) {
	api := fileApi{
		app:             app,
		thumbGenSem:     semaphore.NewWeighted(int64(runtime.NumCPU() + 2)), // the value is arbitrary chosen and may change in the future
		thumbGenPending: new(singleflight.Group),
		thumbGenMaxWait: 60 * time.Second,
	}

	files := r.Group("/files")
	files.Use(ActivityLogger(app))
	files.POST("/token", api.fileToken)
	files.HEAD("/:collection/:recordId/:filename", LoadCollectionContext(api.app), api.download)
	files.GET("/:collection/:recordId/:filename", LoadCollectionContext(api.app), api.download)
}

type fileApi struct {
	app core.App

	// thumbGenSem is a semaphore to prevent too much concurrent
	// requests generating new thumbs at the same time.
	thumbGenSem *semaphore.Weighted

	// thumbGenPending represents a group of currently pending
	// thumb generation processes.
	thumbGenPending *singleflight.Group

	// thumbGenMaxWait is the maximum waiting time for starting a new
	// thumb generation process.
	thumbGenMaxWait time.Duration
}

func (api *fileApi) fileToken(c *gin.Context) {
	event := new(core.FileTokenEvent)
	event.HttpContext = c

	value, exists := c.Get(ContextAdminKey)
	admin, ok := value.(*models.Admin)
	if exists && ok && admin != nil {
		event.Model = admin
		event.Token, _ = tokens.NewAdminFileToken(api.app, admin)
	}

	value, exists = c.Get(ContextAuthRecordKey)
	record, ok := value.(*models.Record)
	if exists && ok && record != nil {
		event.Model = record
		event.Token, _ = tokens.NewRecordFileToken(api.app, record)
	}

	api.app.OnFileBeforeTokenRequest().Trigger(event, func(e *core.FileTokenEvent) error {
		if e.Model == nil || e.Token == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to generate file token."})
			return nil
		}

		return api.app.OnFileAfterTokenRequest().Trigger(event, func(e *core.FileTokenEvent) error {
			if c.Writer.Written() {
				return nil
			}

			c.JSON(http.StatusOK, gin.H{"token": e.Token})
			return nil
		})
	})
}

func (api *fileApi) download(c *gin.Context) {
	value, exists := c.Get(ContextCollectionKey)
	collection, ok := value.(*models.Collection)
	if exists && ok && collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Collection not found."})
		return
	}

	recordId := c.Param("recordId")
	if recordId == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record ID not found."})
		return
	}

	record, err := api.app.Dao().FindRecordById(collection.Id, recordId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	filename := c.Param("filename")

	fileField := record.FindFileFieldByFile(filename)
	if fileField == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File field not found."})
		return
	}

	options, ok := fileField.Options.(*schema.FileOptions)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to load file options."})
		return
	}

	// check whether the request is authorized to view the protected file
	if options.Protected {
		token := c.Query("token")

		adminOrAuthRecord, _ := api.findAdminOrAuthRecordByFileToken(token)

		// create a copy of the cached request data and adjust it for the current auth model
		requestInfo := *RequestInfo(c)
		requestInfo.Context = models.RequestInfoContextProtectedFile
		requestInfo.Admin = nil
		requestInfo.AuthRecord = nil
		if adminOrAuthRecord != nil {
			if admin, _ := adminOrAuthRecord.(*models.Admin); admin != nil {
				requestInfo.Admin = admin
			} else if record, _ := adminOrAuthRecord.(*models.Record); record != nil {
				requestInfo.AuthRecord = record
			}
		}

		if ok, _ := api.app.Dao().CanAccessRecord(record, &requestInfo, record.Collection().ViewRule); !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to access the file resource."})
			return
		}
	}

	baseFilesPath := record.BaseFilesPath()

	// fetch the original view file field related record
	if collection.IsView() {
		fileRecord, err := api.app.Dao().FindRecordByViewFile(collection.Id, fileField.Name, filename)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Failed to fetch view file field record: %v", err)})
			return
		}
		baseFilesPath = fileRecord.BaseFilesPath()
	}

	fsys, err := api.app.NewFilesystem()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Filesystem initialization failure."})
		return
	}
	defer fsys.Close()

	originalPath := baseFilesPath + "/" + filename
	servedPath := originalPath
	servedName := filename

	// check for valid thumb size param
	thumbSize := c.Query("thumb")
	if thumbSize != "" && (list.ExistInSlice(thumbSize, defaultThumbSizes) || list.ExistInSlice(thumbSize, options.Thumbs)) {
		// extract the original file meta attributes and check it existence
		oAttrs, oAttrsErr := fsys.Attributes(originalPath)
		if oAttrsErr != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": oAttrsErr.Error()})
			return
		}

		// check if it is an image
		if list.ExistInSlice(oAttrs.ContentType, imageContentTypes) {
			// add thumb size as file suffix
			servedName = thumbSize + "_" + filename
			servedPath = baseFilesPath + "/thumbs_" + filename + "/" + servedName

			// create a new thumb if it doesn't exist
			if exists, _ := fsys.Exists(servedPath); !exists {
				if err := api.createThumb(c, fsys, originalPath, servedPath, thumbSize); err != nil {
					api.app.Logger().Warn(
						"Fallback to original - failed to create thumb "+servedName,
						slog.Any("error", err),
						slog.String("original", originalPath),
						slog.String("thumb", servedPath),
					)

					// fallback to the original
					servedName = filename
					servedPath = originalPath
				}
			}
		}
	}

	event := new(core.FileDownloadEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Record = record
	event.FileField = fileField
	event.ServedPath = servedPath
	event.ServedName = servedName

	// clickjacking shouldn't be a concern when serving uploaded files,
	// so it safe to unset the global X-Frame-Options to allow files embedding
	// (note: it is out of the hook to allow users to customize the behavior)
	c.Header("X-Frame-Options", "")

	api.app.OnFileDownloadRequest().Trigger(event, func(e *core.FileDownloadEvent) error {
		if c.Writer.Written() {
			return nil
		}

		if err := fsys.Serve(c.Writer, c.Request, e.ServedPath, e.ServedName); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return nil
		}

		return nil
	})
}

func (api *fileApi) findAdminOrAuthRecordByFileToken(fileToken string) (models.Model, error) {
	fileToken = strings.TrimSpace(fileToken)
	if fileToken == "" {
		return nil, errors.New("missing file token")
	}

	claims, _ := security.ParseUnverifiedJWT(strings.TrimSpace(fileToken))
	tokenType := cast.ToString(claims["type"])

	switch tokenType {
	case tokens.TypeAdmin:
		admin, err := api.app.Dao().FindAdminByToken(
			fileToken,
			api.app.Settings().AdminFileToken.Secret,
		)
		if err == nil && admin != nil {
			return admin, nil
		}
	case tokens.TypeAuthRecord:
		record, err := api.app.Dao().FindAuthRecordByToken(
			fileToken,
			api.app.Settings().RecordFileToken.Secret,
		)
		if err == nil && record != nil {
			return record, nil
		}
	}

	return nil, errors.New("missing or invalid file token")
}

func (api *fileApi) createThumb(
	c *gin.Context,
	fsys *filesystem.System,
	originalPath string,
	thumbPath string,
	thumbSize string,
) error {
	ch := api.thumbGenPending.DoChan(thumbPath, func() (any, error) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), api.thumbGenMaxWait)
		defer cancel()

		if err := api.thumbGenSem.Acquire(ctx, 1); err != nil {
			return nil, err
		}
		defer api.thumbGenSem.Release(1)

		return nil, fsys.CreateThumb(originalPath, thumbPath, thumbSize)
	})

	res := <-ch

	api.thumbGenPending.Forget(thumbPath)

	return res.Err
}
