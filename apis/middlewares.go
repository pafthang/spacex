package apis

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/models"
	"github.com/pocketbase/pocketbase/tokens"
	"github.com/pocketbase/pocketbase/tools/list"
	"github.com/pocketbase/pocketbase/tools/routine"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/spf13/cast"
)

// Common request context keys used by the middlewares and api handlers.
const (
	ContextAdminKey      string = "admin"
	ContextAuthRecordKey string = "authRecord"
	ContextCollectionKey string = "collection"
	ContextExecStartKey  string = "execStart"
)

// RequireGuestOnly middleware requires a request to NOT have a valid
// Authorization header.
//
// This middleware is the opposite of [apis.RequireAdminOrRecordAuth()].
func RequireGuestOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := NewBadRequestError("The request can be accessed only by guests.", nil)

		if _, ok := c.Get(ContextAuthRecordKey); ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, err)
			return
		}

		if _, ok := c.Get(ContextAdminKey); ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, err)
			return
		}

		c.Next()
	}
}

// RequireRecordAuth middleware requires a request to have
// a valid record auth Authorization header.
//
// The auth record could be from any collection.
//
// You can further filter the allowed record auth collections by
// specifying their names.
//
// Example:
//
//	apis.RequireRecordAuth()
//
// Or:
//
//	apis.RequireRecordAuth("users", "supervisors")
//
// To restrict the auth record only to the loaded context collection,
// use [apis.RequireSameContextRecordAuth()] instead.
func RequireRecordAuth(optCollectionNames ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, ok := c.Get(ContextAuthRecordKey)
		record, _ := value.(*models.Record)
		if !ok || record == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, NewUnauthorizedError("The request requires valid record authorization token to be set.", nil))
			return
		}

		// check record collection name
		if len(optCollectionNames) > 0 && !list.ExistInSlice(record.Collection().Name, optCollectionNames) {
			c.AbortWithStatusJSON(http.StatusForbidden, NewForbiddenError("The authorized record model is not allowed to perform this action.", nil))
			return
		}

		c.Next()
	}
}

// RequireSameContextRecordAuth middleware requires a request to have
// a valid record Authorization header.
//
// The auth record must be from the same collection already loaded in the context.
func RequireSameContextRecordAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		value, ok := c.Get(ContextAuthRecordKey)
		record, _ := value.(*models.Record)
		if !ok || record == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, NewUnauthorizedError("The request requires valid record authorization token to be set.", nil))
			return
		}

		value, ok = c.Get(ContextCollectionKey)
		collection, _ := value.(*models.Collection)
		if !ok || collection == nil || record.Collection().Id != collection.Id {
			c.AbortWithStatusJSON(http.StatusForbidden, NewForbiddenError(fmt.Sprintf("The request requires auth record from %s collection.", record.Collection().Name), nil))
			return
		}

		c.Next()
	}
}

// RequireAdminAuth middleware requires a request to have
// a valid admin Authorization header.
func RequireAdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		value, ok := c.Get(ContextAdminKey)
		admin, _ := value.(*models.Admin)
		if !ok || admin == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, NewUnauthorizedError("The request requires valid admin authorization token to be set.", nil))
			return
		}

		c.Next()
	}
}

// RequireAdminAuthOnlyIfAny middleware requires a request to have
// a valid admin Authorization header ONLY if the application has
// at least 1 existing Admin model.
func RequireAdminAuthOnlyIfAny(app core.App) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, ok := c.Get(ContextAdminKey)
		admin, _ := value.(*models.Admin)
		if ok && admin != nil {
			c.Next()
			return
		}

		totalAdmins, err := app.Dao().TotalAdmins()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, NewBadRequestError("Failed to fetch admins info.", err))
			return
		}

		if totalAdmins == 0 {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, NewUnauthorizedError("The request requires valid admin authorization token to be set.", nil))
	}
}

// RequireAdminOrRecordAuth middleware requires a request to have
// a valid admin or record Authorization header set.
//
// You can further filter the allowed auth record collections by providing their names.
//
// This middleware is the opposite of [apis.RequireGuestOnly()].
func RequireAdminOrRecordAuth(optCollectionNames ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, ok := c.Get(ContextAdminKey)
		admin, _ := value.(*models.Admin)
		if ok && admin != nil {
			c.Next()
			return
		}

		value, ok = c.Get(ContextAuthRecordKey)
		record, _ := value.(*models.Record)
		if !ok || record == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, NewUnauthorizedError("The request requires admin or record authorization token to be set.", nil))
			return
		}

		// Измененная часть: убрана проверка record != nil
		if len(optCollectionNames) > 0 && !list.ExistInSlice(record.Collection().Name, optCollectionNames) {
			c.AbortWithStatusJSON(http.StatusForbidden, NewForbiddenError("The authorized record model is not allowed to perform this action.", nil))
			return
		}

		c.Next()
	}
}

// RequireAdminOrOwnerAuth middleware requires a request to have
// a valid admin or auth record owner Authorization header set.
//
// This middleware is similar to [apis.RequireAdminOrRecordAuth()] but
// for the auth record token expects to have the same id as the path
// parameter ownerIdParam (default to "id" if empty).
func RequireAdminOrOwnerAuth(ownerIdParam string) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, ok := c.Get(ContextAdminKey)
		admin, _ := value.(*models.Admin)
		if ok && admin != nil {
			c.Next()
			return
		}

		value, ok = c.Get(ContextAuthRecordKey)
		record, _ := value.(*models.Record)
		if !ok || record == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, NewUnauthorizedError("The request requires admin or record authorization token to be set.", nil))
			return
		}

		if ownerIdParam == "" {
			ownerIdParam = "id"
		}
		ownerId := c.Param(ownerIdParam)

		// note: it is "safe" to compare only the record id since the auth
		// record ids are treated as unique across all auth collections
		if record.Id != ownerId {
			c.AbortWithStatusJSON(http.StatusForbidden, NewForbiddenError("You are not allowed to perform this request.", nil))
			return
		}

		c.Next()
	}
}

// LoadAuthContext middleware reads the Authorization request header
// and loads the token related record or admin instance into the
// request's context.
//
// This middleware is expected to be already registered by default for all routes.
func LoadAuthContext(app core.App) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("Authorization")
		if token == "" {
			c.Next()
			return
		}

		// the schema is not required and it is only for
		// compatibility with the defaults of some HTTP clients
		token = strings.TrimPrefix(token, "Bearer ")

		claims, _ := security.ParseUnverifiedJWT(token)
		tokenType := cast.ToString(claims["type"])

		switch tokenType {
		case tokens.TypeAdmin:
			admin, err := app.Dao().FindAdminByToken(
				token,
				app.Settings().AdminAuthToken.Secret,
			)
			if err == nil && admin != nil {
				c.Set(ContextAdminKey, admin)
			}
		case tokens.TypeAuthRecord:
			record, err := app.Dao().FindAuthRecordByToken(
				token,
				app.Settings().RecordAuthToken.Secret,
			)
			if err == nil && record != nil {
				c.Set(ContextAuthRecordKey, record)
			}
		}

		c.Next()
	}
}

// LoadCollectionContext middleware finds the collection with related
// path identifier and loads it into the request context.
//
// Set optCollectionTypes to further filter the found collection by its type.
func LoadCollectionContext(app core.App, optCollectionTypes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if param := c.Param("collection"); param != "" {
			collection, err := core.FindCachedCollectionByNameOrId(app, param)
			if err != nil || collection == nil {
				c.AbortWithStatusJSON(http.StatusNotFound, NewNotFoundError("", err))
				return
			}

			if len(optCollectionTypes) > 0 && !list.ExistInSlice(collection.Type, optCollectionTypes) {
				c.AbortWithStatusJSON(http.StatusBadRequest, NewBadRequestError("Unsupported collection type.", nil))
				return
			}

			c.Set(ContextCollectionKey, collection)
		}

		c.Next()
	}
}

// ActivityLogger middleware takes care to save the request information
// into the logs database.
//
// The middleware does nothing if the app logs retention period is zero
// (aka. app.Settings().Logs.MaxDays = 0).
func ActivityLogger(app core.App) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if c.Writer.Status() >= 400 {
			return
		}

		logRequest(app, c, nil)
	}
}

func logRequest(app core.App, c *gin.Context, err *ApiError) {
	// no logs retention
	if app.Settings().Logs.MaxDays == 0 {
		return
	}

	attrs := make([]any, 0, 15)

	attrs = append(attrs, slog.String("type", "request"))

	value, ok := c.Get(ContextExecStartKey)
	started := cast.ToTime(value)
	if ok && !started.IsZero() {
		attrs = append(attrs, slog.Float64("execTime", float64(time.Since(started))/float64(time.Millisecond)))
	}

	httpRequest := c.Request
	httpResponse := c.Writer
	method := strings.ToUpper(httpRequest.Method)
	status := httpResponse.Status()
	requestUri := httpRequest.URL.RequestURI()

	// parse the request error
	if err != nil {
		status = err.Code
		attrs = append(
			attrs,
			slog.String("error", err.Message),
			slog.Any("details", err.RawData()),
		)
	}

	requestAuth := models.RequestAuthGuest
	if _, ok := c.Get(ContextAuthRecordKey); ok {
		requestAuth = models.RequestAuthRecord
	} else if _, ok := c.Get(ContextAdminKey); ok {
		requestAuth = models.RequestAuthAdmin
	}

	attrs = append(
		attrs,
		slog.String("url", requestUri),
		slog.String("method", method),
		slog.Int("status", status),
		slog.String("auth", requestAuth),
		slog.String("referer", httpRequest.Referer()),
		slog.String("userAgent", httpRequest.UserAgent()),
	)

	if app.Settings().Logs.LogIp {
		ip, _, _ := net.SplitHostPort(httpRequest.RemoteAddr)
		attrs = append(
			attrs,
			slog.String("userIp", realUserIp(httpRequest, ip)),
			slog.String("remoteIp", ip),
		)
	}

	// don't block on logs write
	routine.FireAndForget(func() {
		message := method + " "

		if escaped, err := url.PathUnescape(requestUri); err == nil {
			message += escaped
		} else {
			message += requestUri
		}

		if err != nil {
			app.Logger().Error(message, attrs...)
		} else {
			app.Logger().Info(message, attrs...)
		}
	})
}

// Returns the "real" user IP from common proxy headers (or fallbackIp if none is found).
//
// The returned IP value shouldn't be trusted if not behind a trusted reverse proxy!
func realUserIp(r *http.Request, fallbackIp string) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}

	if ip := r.Header.Get("Fly-Client-IP"); ip != "" {
		return ip
	}

	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	if ipsList := r.Header.Get("X-Forwarded-For"); ipsList != "" {
		// extract the first non-empty leftmost-ish ip
		ips := strings.Split(ipsList, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				return ip
			}
		}
	}

	return fallbackIp
}

// @todo consider removing as this may no longer be needed due to the custom rest.MultiBinder.
//
// eagerRequestInfoCache ensures that the request data is cached in the request
// context to allow reading for example the json request body data more than once.
func eagerRequestInfoCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		// currently we are eagerly caching only the requests with body
		case "POST", "PUT", "PATCH", "DELETE":
			RequestInfo(c)
		}

		c.Next()
	}
}
