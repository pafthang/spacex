package rest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cast"
)

// MultipartJsonKey is the key for the special multipart/form-data
// handling allowing reading serialized json payload without normalization.
const MultipartJsonKey string = "@jsonPayload"

// MultiBinder is similar to the default Gin binder but uses slightly different
// application/json and multipart/form-data bind methods to accommodate better
// the PocketBase router needs.
type MultiBinder struct{}

// Bind implements the [Binder.Bind] method.
//
// Bind is almost identical to the default Gin binder but uses the
// [rest.BindBody] function for binding the request body.
func (b *MultiBinder) Bind(c *gin.Context, i interface{}) (err error) {
	if err := c.ShouldBindUri(i); err != nil {
		return err
	}

	// Only bind query parameters for GET/DELETE/HEAD to avoid unexpected behavior with destination struct binding from body.
	// For example a request URL `&id=1&lang=en` with body `{"id":100,"lang":"de"}` would lead to precedence issues.
	method := c.Request.Method
	if method == http.MethodGet || method == http.MethodDelete || method == http.MethodHead {
		if err = c.ShouldBindQuery(i); err != nil {
			return err
		}
	}

	return BindBody(c, i)
}

// BindBody binds request body content to i.
//
// This is similar to the default Gin binder, but for JSON requests uses
// custom json reader that **copies** the request body, allowing multiple reads.
func BindBody(c *gin.Context, i any) error {
	req := c.Request
	if req.ContentLength == 0 {
		return nil
	}

	ctype := req.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ctype, "application/json"):
		err := CopyJsonBody(c.Request, i)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return err
		}
		return nil
	case strings.HasPrefix(ctype, "application/x-www-form-urlencoded"), strings.HasPrefix(ctype, "multipart/form-data"):
		return bindFormData(c, i)
	}

	// fallback to the default binder
	return c.ShouldBind(i)
}

// CopyJsonBody reads the request body into i by
// creating a copy of `r.Body` to allow multiple reads.
func CopyJsonBody(r *http.Request, i any) error {
	body := r.Body

	// this usually shouldn't be needed because the Server calls close
	// for us but we are changing the request body with a new reader
	defer body.Close()

	limitReader := io.LimitReader(body, DefaultMaxMemory)

	bodyBytes, readErr := io.ReadAll(limitReader)
	if readErr != nil {
		return readErr
	}

	err := json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(i)

	// set new body reader
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	return err
}

// Custom multipart/form-data binder that implements an additional handling like
// loading a serialized json payload or properly scan array values when a map destination is used.
func bindFormData(c *gin.Context, i any) error {
	if i == nil {
		return nil
	}

	values, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return err
	}

	if len(values.Value) == 0 {
		return nil
	}

	// special case to allow submitting json without normalization
	// alongside the other multipart/form-data values
	jsonPayloadValues := values.Value[MultipartJsonKey]
	for _, payload := range jsonPayloadValues {
		json.Unmarshal([]byte(payload), i)
	}

	rt := reflect.TypeOf(i).Elem()

	// map
	if rt.Kind() == reflect.Map {
		rv := reflect.ValueOf(i).Elem()

		for k, v := range values.Value {
			if k == MultipartJsonKey {
				continue
			}

			if total := len(v); total == 1 {
				rv.SetMapIndex(reflect.ValueOf(k), reflect.ValueOf(normalizeMultipartValue(v[0])))
			} else {
				normalized := make([]any, total)
				for i, vItem := range v {
					normalized[i] = normalizeMultipartValue(vItem)
				}
				rv.SetMapIndex(reflect.ValueOf(k), reflect.ValueOf(normalized))
			}
		}

		return nil
	}

	// anything else
	return c.ShouldBind(i)
}

// In order to support more seamlessly both json and multipart/form-data requests,
// the following normalization rules are applied for plain multipart string values:
// - "true" is converted to the json `true`
// - "false" is converted to the json `false`
// - numeric (non-scientific) strings are converted to json number
// - any other string (empty string too) is left as it is
func normalizeMultipartValue(raw string) any {
	switch raw {
	case "":
		return raw
	case "true":
		return true
	case "false":
		return false
	default:
		if raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9') {
			if v, err := cast.ToFloat64E(raw); err == nil {
				return v
			}
		}

		return raw
	}
}
