package apis

import (
	"net/http"

	"github.com/gin-gonic/gin"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/forms"
	"github.com/pocketbase/pocketbase/models/settings"
)

// bindSettingsApi registers the settings api endpoints.
func bindSettingsApi(app core.App, api *gin.RouterGroup) {
	settingsApiInstance := settingsApi{app: app}

	subGroup := api.Group("/settings", ActivityLogger(app), RequireAdminAuth())
	subGroup.GET("", settingsApiInstance.list)
	subGroup.PATCH("", settingsApiInstance.set)
	subGroup.POST("/test/s3", settingsApiInstance.testS3)
	subGroup.POST("/test/email", settingsApiInstance.testEmail)
	subGroup.POST("/apple/generate-client-secret", settingsApiInstance.generateAppleClientSecret)
}

type settingsApi struct {
	app core.App
}

func (api *settingsApi) list(c *gin.Context) {
	settings, err := api.app.Settings().RedactClone()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	event := new(core.SettingsListEvent)
	event.HttpContext = c
	event.RedactedSettings = settings

	api.app.OnSettingsListRequest().Trigger(event, func(e *core.SettingsListEvent) error {
		if e.HttpContext.Writer.Written() {
			return nil
		}

		c.JSON(http.StatusOK, e.RedactedSettings)
		return nil
	})
}

func (api *settingsApi) set(c *gin.Context) {
	form := forms.NewSettingsUpsert(api.app)

	// load request
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data."})
		return
	}

	event := new(core.SettingsUpdateEvent)
	event.HttpContext = c
	event.OldSettings = api.app.Settings()

	// update the settings
	form.Submit(func(next forms.InterceptorNextFunc[*settings.Settings]) forms.InterceptorNextFunc[*settings.Settings] {
		return func(s *settings.Settings) error {
			event.NewSettings = s

			return api.app.OnSettingsBeforeUpdateRequest().Trigger(event, func(e *core.SettingsUpdateEvent) error {
				if err := next(e.NewSettings); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while submitting the form."})
					return err
				}

				return api.app.OnSettingsAfterUpdateRequest().Trigger(event, func(e *core.SettingsUpdateEvent) error {
					if e.HttpContext.Writer.Written() {
						return nil
					}

					redactedSettings, err := api.app.Settings().RedactClone()
					if err != nil {
						c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
						return err
					}

					c.JSON(http.StatusOK, redactedSettings)
					return nil
				})
			})
		}
	})
}

func (api *settingsApi) testS3(c *gin.Context) {
	form := forms.NewTestS3Filesystem(api.app)

	// load request
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data."})
		return
	}

	// send
	if err := form.Submit(); err != nil {
		// form error
		if fErr, ok := err.(validation.Errors); ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to test the S3 filesystem.", "details": fErr})
			return
		}

		// mailer error
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to test the S3 filesystem. Raw error: " + err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func (api *settingsApi) testEmail(c *gin.Context) {
	form := forms.NewTestEmailSend(api.app)

	// load request
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data."})
		return
	}

	// send
	if err := form.Submit(); err != nil {
		// form error
		if fErr, ok := err.(validation.Errors); ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to send the test email.", "details": fErr})
			return
		}

		// mailer error
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to send the test email. Raw error: " + err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func (api *settingsApi) generateAppleClientSecret(c *gin.Context) {
	form := forms.NewAppleClientSecretCreate(api.app)

	// load request
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data."})
		return
	}

	// generate
	secret, err := form.Submit()
	if err != nil {
		// form error
		if fErr, ok := err.(validation.Errors); ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid client secret data.", "details": fErr})
			return
		}

		// secret generation error
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to generate client secret. Raw error: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"secret": secret})
}
