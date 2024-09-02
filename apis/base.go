// Package apis implements the default PocketBase api services and middlewares.
package apis

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/ui"
	"github.com/spf13/cast"
)

const trailedAdminPath = "/_/"

// InitApi creates a configured gin instance with registered
// system and app specific routes and middlewares.
func InitApi(app core.App) (*gin.Engine, error) {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.Use(func(c *gin.Context) {
		c.Set(ContextExecStartKey, time.Now())
		c.Next()
	})

	// custom error handler
	r.Use(func(c *gin.Context) {
		c.Next()
		err := c.Errors.Last()
		if err == nil {
			return
		}

		var apiErr *ApiError

		if errors.As(err.Err, &apiErr) {
			// already an api error...
		} else if v, ok := err.Err.(*gin.Error); ok {
			msg := fmt.Sprintf("%v", v.Err)
			apiErr = NewApiError(int(v.Type), msg, v) // Convert v.Type to int
		} else {
			if errors.Is(err.Err, sql.ErrNoRows) {
				apiErr = NewNotFoundError("", err.Err)
			} else {
				apiErr = NewBadRequestError("", err.Err)
			}
		}

		logRequest(app, c, apiErr)

		if c.Writer.Written() {
			return // already committed
		}

		event := new(core.ApiErrorEvent)
		event.HttpContext = c
		event.Error = apiErr

		// send error response
		hookErr := app.OnBeforeApiError().Trigger(event, func(e *core.ApiErrorEvent) error {
			if c.Writer.Written() {
				return nil
			}

			if c.Request.Method == http.MethodHead {
				c.Status(apiErr.Code)
				return nil
			}

			c.JSON(apiErr.Code, apiErr)
			return nil
		})

		if hookErr == nil {
			if err := app.OnAfterApiError().Trigger(event); err != nil {
				app.Logger().Debug("OnAfterApiError failure", "error", err.Error())
			}
		} else {
			app.Logger().Debug("OnBeforeApiError error (truly rare case, eg. client already disconnected)", "error", hookErr.Error())
		}
	})

	// admin ui routes
	bindStaticAdminUI(app, r)

	// default routes
	api := r.Group("/api", eagerRequestInfoCache())
	bindSettingsApi(app, api)
	bindAdminApi(app, api)
	bindCollectionApi(app, api)
	bindRecordCrudApi(app, api)
	bindRecordAuthApi(app, api)
	bindFileApi(app, api)
	bindRealtimeApi(app, api)
	bindLogsApi(app, api)
	bindHealthApi(app, api)
	bindBackupApi(app, api)

	// catch all any route
	r.NoRoute(ActivityLogger(app))
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not Found"})
	})

	return r, nil
}

// StaticDirectoryHandler is similar to `gin.StaticFS`
// but without the directory redirect which conflicts with RemoveTrailingSlash middleware.
//
// If a file resource is missing and indexFallback is set, the request
// will be forwarded to the base index.html (useful also for SPA).
func StaticDirectoryHandler(fileSystem fs.FS, indexFallback bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		p := c.Param("filepath")

		// escape url path
		tmpPath, err := url.PathUnescape(p)
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("failed to unescape path variable: %v", err))
			return
		}
		p = tmpPath

		// fs.FS.Open() already assumes that file names are relative to FS root path and considers name with prefix `/` as invalid
		name := filepath.ToSlash(filepath.Clean(strings.TrimPrefix(p, "/")))

		// Use the correct method to serve files
		c.FileFromFS(name, http.FS(fileSystem))

		if indexFallback && errors.Is(err, fs.ErrNotExist) {
			c.FileFromFS("index.html", http.FS(fileSystem))
		}
	}
}

// bindStaticAdminUI registers the endpoints that serves the static admin UI.
func bindStaticAdminUI(app core.App, r *gin.Engine) {
	// redirect to trailing slash to ensure that relative urls will still work properly
	r.GET(
		strings.TrimRight(trailedAdminPath, "/"),
		func(c *gin.Context) {
			c.Redirect(http.StatusTemporaryRedirect, strings.TrimLeft(trailedAdminPath, "/"))
		},
	)

	// serves static files from the /ui/dist directory
	// (similar to gin.StaticFS but with gzip middleware enabled)
	r.GET(
		trailedAdminPath+"*",
		StaticDirectoryHandler(ui.DistDirFS, false),
		installerRedirect(app),
		uiCacheControl(),
		gin.WrapH(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, r.URL.Path)
		})),
	)
}

func uiCacheControl() gin.HandlerFunc {
	return func(c *gin.Context) {
		// add default Cache-Control header for all Admin UI resources
		// (ignoring the root admin path)
		if c.Request.URL.Path != trailedAdminPath {
			c.Header("Cache-Control", "max-age=1209600, stale-while-revalidate=86400")
		}

		c.Next()
	}
}

const hasAdminsCacheKey = "@hasAdmins"

func updateHasAdminsCache(app core.App) error {
	total, err := app.Dao().TotalAdmins()
	if err != nil {
		return err
	}

	app.Store().Set(hasAdminsCacheKey, total > 0)

	return nil
}

// installerRedirect redirects the user to the installer admin UI page
// when the application needs some preliminary configurations to be done.
func installerRedirect(app core.App) gin.HandlerFunc {
	// keep hasAdminsCacheKey value up-to-date
	app.OnAdminAfterCreateRequest().Add(func(data *core.AdminCreateEvent) error {
		return updateHasAdminsCache(app)
	})

	app.OnAdminAfterDeleteRequest().Add(func(data *core.AdminDeleteEvent) error {
		return updateHasAdminsCache(app)
	})

	return func(c *gin.Context) {
		// skip redirect checks for non-root level index.html requests
		path := c.Request.URL.Path
		if path != trailedAdminPath && path != trailedAdminPath+"index.html" {
			c.Next()
			return
		}

		hasAdmins := cast.ToBool(app.Store().Get(hasAdminsCacheKey))

		if !hasAdmins {
			// update the cache to make sure that the admin wasn't created by another process
			if err := updateHasAdminsCache(app); err != nil {
				c.String(http.StatusInternalServerError, err.Error())
				return
			}
			hasAdmins = cast.ToBool(app.Store().Get(hasAdminsCacheKey))
		}

		_, hasInstallerParam := c.Request.URL.Query()["installer"]

		if !hasAdmins && !hasInstallerParam {
			// redirect to the installer page
			c.Redirect(http.StatusTemporaryRedirect, "?installer#")
			return
		}

		if hasAdmins && hasInstallerParam {
			// clear the installer param
			c.Redirect(http.StatusTemporaryRedirect, "?")
			return
		}

		c.Next()
	}
}
