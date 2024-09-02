package apis

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/daos"
	"github.com/pocketbase/pocketbase/forms"
	"github.com/pocketbase/pocketbase/mails"
	"github.com/pocketbase/pocketbase/models"
	"github.com/pocketbase/pocketbase/models/schema"
	"github.com/pocketbase/pocketbase/resolvers"
	"github.com/pocketbase/pocketbase/tools/auth"
	"github.com/pocketbase/pocketbase/tools/routine"
	"github.com/pocketbase/pocketbase/tools/search"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pocketbase/pocketbase/tools/subscriptions"
	"github.com/pocketbase/pocketbase/tools/types"
	"golang.org/x/oauth2"
)

// bindRecordAuthApi registers the auth record api endpoints and
// the corresponding handlers.
func bindRecordAuthApi(app core.App, api *gin.RouterGroup) {
	recordApi := recordAuthApi{app: app}

	// global oauth2 subscription redirect handler
	api.GET("/oauth2-redirect", recordApi.oauth2SubscriptionRedirect)
	api.POST("/oauth2-redirect", recordApi.oauth2SubscriptionRedirect) // needed in case of response_mode=form_post

	// common collection record related routes
	subGroup := api.Group("/collections/:collection")
	subGroup.Use(ActivityLogger(app), LoadCollectionContext(app, models.CollectionTypeAuth))
	subGroup.GET("/auth-methods", recordApi.authMethods)
	subGroup.POST("/auth-refresh", recordApi.authRefresh, RequireSameContextRecordAuth())
	subGroup.POST("/auth-with-oauth2", recordApi.authWithOAuth2)
	subGroup.POST("/auth-with-password", recordApi.authWithPassword)
	subGroup.POST("/request-password-reset", recordApi.requestPasswordReset)
	subGroup.POST("/confirm-password-reset", recordApi.confirmPasswordReset)
	subGroup.POST("/request-verification", recordApi.requestVerification)
	subGroup.POST("/confirm-verification", recordApi.confirmVerification)
	subGroup.POST("/request-email-change", recordApi.requestEmailChange, RequireSameContextRecordAuth())
	subGroup.POST("/confirm-email-change", recordApi.confirmEmailChange)
	subGroup.GET("/records/:id/external-auths", recordApi.listExternalAuths, RequireAdminOrOwnerAuth("id"))
	subGroup.DELETE("/records/:id/external-auths/:provider", recordApi.unlinkExternalAuth, RequireAdminOrOwnerAuth("id"))
}

type recordAuthApi struct {
	app core.App
}

func (api *recordAuthApi) authRefresh(c *gin.Context) {
	recordValue, exists := c.Get(ContextAuthRecordKey)
	record, _ := recordValue.(*models.Record)
	if !exists || record == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing auth record context."})
		return
	}

	event := new(core.RecordAuthRefreshEvent)
	event.HttpContext = c
	event.Collection = record.Collection()
	event.Record = record

	api.app.OnRecordBeforeAuthRefreshRequest().Trigger(event, func(e *core.RecordAuthRefreshEvent) error {
		return api.app.OnRecordAfterAuthRefreshRequest().Trigger(event, func(e *core.RecordAuthRefreshEvent) error {
			return RecordAuthResponse(api.app, e.HttpContext, e.Record, nil)
		})
	})
}

type providerInfo struct {
	Name                string `json:"name"`
	DisplayName         string `json:"displayName"`
	State               string `json:"state"`
	AuthUrl             string `json:"authUrl"`
	CodeVerifier        string `json:"codeVerifier"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
}

func (api *recordAuthApi) authMethods(c *gin.Context) {
	collectionValue, exists := c.Get(ContextCollectionKey)
	collection, _ := collectionValue.(*models.Collection)
	if !exists || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	authOptions := collection.AuthOptions()

	result := struct {
		AuthProviders    []providerInfo `json:"authProviders"`
		UsernamePassword bool           `json:"usernamePassword"`
		EmailPassword    bool           `json:"emailPassword"`
		OnlyVerified     bool           `json:"onlyVerified"`
	}{
		UsernamePassword: authOptions.AllowUsernameAuth,
		EmailPassword:    authOptions.AllowEmailAuth,
		OnlyVerified:     authOptions.OnlyVerified,
		AuthProviders:    []providerInfo{},
	}

	if !authOptions.AllowOAuth2Auth {
		c.JSON(http.StatusOK, result)
		return
	}

	nameConfigMap := api.app.Settings().NamedAuthProviderConfigs()
	for name, config := range nameConfigMap {
		if !config.Enabled {
			continue
		}

		provider, err := auth.NewProviderByName(name)
		if err != nil {
			api.app.Logger().Debug("Missing or invalid provider name", "name", name)
			continue // skip provider
		}

		if err := config.SetupProvider(provider); err != nil {
			api.app.Logger().Debug("Failed to setup provider", "name", name, "error", err.Error())
			continue // skip provider
		}

		info := providerInfo{
			Name:        name,
			DisplayName: provider.DisplayName(),
			State:       security.RandomString(30),
		}

		if info.DisplayName == "" {
			info.DisplayName = name
		}

		urlOpts := []oauth2.AuthCodeOption{}

		// custom providers url options
		switch name {
		case auth.NameApple:
			urlOpts = append(urlOpts, oauth2.SetAuthURLParam("response_mode", "form_post"))
		}

		if provider.PKCE() {
			info.CodeVerifier = security.RandomString(43)
			info.CodeChallenge = security.S256Challenge(info.CodeVerifier)
			info.CodeChallengeMethod = "S256"
			urlOpts = append(urlOpts,
				oauth2.SetAuthURLParam("code_challenge", info.CodeChallenge),
				oauth2.SetAuthURLParam("code_challenge_method", info.CodeChallengeMethod),
			)
		}

		info.AuthUrl = provider.BuildAuthUrl(info.State, urlOpts...) + "&redirect_uri=" // empty redirect_uri so that users can append their redirect url

		result.AuthProviders = append(result.AuthProviders, info)
	}

	// sort providers
	sort.SliceStable(result.AuthProviders, func(i, j int) bool {
		return result.AuthProviders[i].Name < result.AuthProviders[j].Name
	})

	c.JSON(http.StatusOK, result)
}

func (api *recordAuthApi) authWithOAuth2(c *gin.Context) {
	collectionValue, exists := c.Get(ContextCollectionKey)
	collection, _ := collectionValue.(*models.Collection)
	if !exists || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	if !collection.AuthOptions().AllowOAuth2Auth {
		c.JSON(http.StatusBadRequest, gin.H{"error": "The collection is not configured to allow OAuth2 authentication."})
		return
	}

	var fallbackAuthRecord *models.Record

	loggedAuthRecordValue, _ := c.Get(ContextAuthRecordKey)
	loggedAuthRecord, _ := loggedAuthRecordValue.(*models.Record)
	if loggedAuthRecord != nil && loggedAuthRecord.Collection().Id == collection.Id {
		fallbackAuthRecord = loggedAuthRecord
	}

	form := forms.NewRecordOAuth2Login(api.app, collection, fallbackAuthRecord)
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data.", "details": err.Error()})
		return
	}

	event := new(core.RecordAuthWithOAuth2Event)
	event.HttpContext = c
	event.Collection = collection
	event.ProviderName = form.Provider

	form.SetBeforeNewRecordCreateFunc(func(createForm *forms.RecordUpsert, authRecord *models.Record, authUser *auth.AuthUser) error {
		return createForm.DrySubmit(func(txDao *daos.Dao) error {
			event.IsNewRecord = true

			// clone the current request data and assign the form create data as its body data
			requestInfo := *RequestInfo(c)
			requestInfo.Context = models.RequestInfoContextOAuth2
			requestInfo.Data = form.CreateData

			createRuleFunc := func(q *dbx.SelectQuery) error {
				adminValue, _ := c.Get(ContextAdminKey)
				admin, _ := adminValue.(*models.Admin)
				if admin != nil {
					return nil // either admin or the rule is empty
				}

				if collection.CreateRule == nil {
					return errors.New("only admins can create new accounts with OAuth2")
				}

				if *collection.CreateRule != "" {
					resolver := resolvers.NewRecordFieldResolver(txDao, collection, &requestInfo, true)
					expr, err := search.FilterData(*collection.CreateRule).BuildExpr(resolver)
					if err != nil {
						return err
					}
					resolver.UpdateQuery(q)
					q.AndWhere(expr)
				}

				return nil
			}

			if _, err := txDao.FindRecordById(collection.Id, createForm.Id, createRuleFunc); err != nil {
				return fmt.Errorf("failed create rule constraint: %w", err)
			}

			return nil
		})
	})

	_, _, submitErr := form.Submit(func(next forms.InterceptorNextFunc[*forms.RecordOAuth2LoginData]) forms.InterceptorNextFunc[*forms.RecordOAuth2LoginData] {
		return func(data *forms.RecordOAuth2LoginData) error {
			event.Record = data.Record
			event.OAuth2User = data.OAuth2User
			event.ProviderClient = data.ProviderClient
			event.IsNewRecord = data.Record == nil

			return api.app.OnRecordBeforeAuthWithOAuth2Request().Trigger(event, func(e *core.RecordAuthWithOAuth2Event) error {
				data.Record = e.Record
				data.OAuth2User = e.OAuth2User

				if err := next(data); err != nil {
					return NewBadRequestError("Failed to authenticate.", err)
				}

				e.Record = data.Record
				e.OAuth2User = data.OAuth2User

				meta := struct {
					*auth.AuthUser
					IsNew bool `json:"isNew"`
				}{
					AuthUser: e.OAuth2User,
					IsNew:    event.IsNewRecord,
				}

				return api.app.OnRecordAfterAuthWithOAuth2Request().Trigger(event, func(e *core.RecordAuthWithOAuth2Event) error {
					// clear the lastLoginAlertSentAt field so that we can enforce password auth notifications
					if !e.Record.LastLoginAlertSentAt().IsZero() {
						e.Record.Set(schema.FieldNameLastLoginAlertSentAt, "")
						if err := api.app.Dao().SaveRecord(e.Record); err != nil {
							api.app.Logger().Warn("Failed to reset lastLoginAlertSentAt", "error", err, "recordId", e.Record.Id)
						}
					}

					return RecordAuthResponse(api.app, e.HttpContext, e.Record, meta)
				})
			})
		}
	})

	c.JSON(http.StatusOK, submitErr)
}

func (api *recordAuthApi) authWithPassword(c *gin.Context) {
	collectionValue, exists := c.Get(ContextCollectionKey)
	collection, _ := collectionValue.(*models.Collection)
	if !exists || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	form := forms.NewRecordPasswordLogin(api.app, collection)
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data.", "details": err.Error()})
		return
	}

	event := new(core.RecordAuthWithPasswordEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Password = form.Password
	event.Identity = form.Identity

	_, submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeAuthWithPasswordRequest().Trigger(event, func(e *core.RecordAuthWithPasswordEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("Failed to authenticate.", err)
				}

				// @todo remove after the refactoring
				if collection.AuthOptions().AllowOAuth2Auth && e.Record.Email() != "" {
					externalAuths, err := api.app.Dao().FindAllExternalAuthsByRecord(e.Record)
					if err != nil {
						return NewBadRequestError("Failed to authenticate.", err)
					}
					if len(externalAuths) > 0 {
						lastLoginAlert := e.Record.LastLoginAlertSentAt().Time()

						// send an email alert if the password auth is after OAuth2 auth (lastLoginAlert will be empty)
						// or if it has been ~7 days since the last alert
						if lastLoginAlert.IsZero() || time.Now().UTC().Sub(lastLoginAlert).Hours() > 168 {
							providerNames := make([]string, len(externalAuths))
							for i, ea := range externalAuths {
								var name string
								if provider, err := auth.NewProviderByName(ea.Provider); err == nil {
									name = provider.DisplayName()
								}
								if name == "" {
									name = ea.Provider
								}
								providerNames[i] = name
							}

							if err := mails.SendRecordPasswordLoginAlert(api.app, e.Record, providerNames...); err != nil {
								return NewBadRequestError("Failed to authenticate.", err)
							}

							e.Record.SetLastLoginAlertSentAt(types.NowDateTime())
							if err := api.app.Dao().SaveRecord(e.Record); err != nil {
								api.app.Logger().Warn("Failed to update lastLoginAlertSentAt", "error", err, "recordId", e.Record.Id)
							}
						}
					}
				}

				return api.app.OnRecordAfterAuthWithPasswordRequest().Trigger(event, func(e *core.RecordAuthWithPasswordEvent) error {
					return RecordAuthResponse(api.app, e.HttpContext, e.Record, nil)
				})
			})
		}
	})

	c.JSON(http.StatusOK, submitErr)
}

func (api *recordAuthApi) requestPasswordReset(c *gin.Context) {
	collectionValue, exists := c.Get(ContextCollectionKey)
	collection, _ := collectionValue.(*models.Collection)
	if !exists || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	authOptions := collection.AuthOptions()
	if !authOptions.AllowUsernameAuth && !authOptions.AllowEmailAuth {
		c.JSON(http.StatusBadRequest, gin.H{"error": "The collection is not configured to allow password authentication."})
		return
	}

	form := forms.NewRecordPasswordResetRequest(api.app, collection)
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data.", "details": err.Error()})
		return
	}

	if err := form.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while validating the form.", "details": err.Error()})
		return
	}

	event := new(core.RecordRequestPasswordResetEvent)
	event.HttpContext = c
	event.Collection = collection

	submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeRequestPasswordResetRequest().Trigger(event, func(e *core.RecordRequestPasswordResetEvent) error {
				// run in background because we don't need to show the result to the client
				routine.FireAndForget(func() {
					if err := next(e.Record); err != nil {
						api.app.Logger().Debug("Failed to send password reset email", "error", err.Error())
					}
				})

				return api.app.OnRecordAfterRequestPasswordResetRequest().Trigger(event, func(e *core.RecordRequestPasswordResetEvent) error {
					if e.HttpContext.Writer.Written() {
						return nil
					}

					e.HttpContext.Writer.WriteHeader(http.StatusNoContent)
					return nil
				})
			})
		}
	})

	// eagerly write 204 response and skip submit errors
	// as a measure against emails enumeration
	if !c.Writer.Written() {
		c.Status(http.StatusNoContent)
	}

	c.JSON(http.StatusOK, submitErr)
}

func (api *recordAuthApi) confirmPasswordReset(c *gin.Context) {
	collectionValue, exists := c.Get(ContextCollectionKey)
	collection, _ := collectionValue.(*models.Collection)
	if !exists || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	form := forms.NewRecordPasswordResetConfirm(api.app, collection)
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data.", "details": err.Error()})
		return
	}

	event := new(core.RecordConfirmPasswordResetEvent)
	event.HttpContext = c
	event.Collection = collection

	_, submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeConfirmPasswordResetRequest().Trigger(event, func(e *core.RecordConfirmPasswordResetEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("Failed to set new password.", err)
				}

				return api.app.OnRecordAfterConfirmPasswordResetRequest().Trigger(event, func(e *core.RecordConfirmPasswordResetEvent) error {
					if e.HttpContext.Writer.Written() {
						return nil
					}

					e.HttpContext.Writer.WriteHeader(http.StatusNoContent)
					return nil
				})
			})
		}
	})

	c.JSON(http.StatusOK, submitErr)
}

func (api *recordAuthApi) requestVerification(c *gin.Context) {
	collectionValue, exists := c.Get(ContextCollectionKey)
	collection, _ := collectionValue.(*models.Collection)
	if !exists || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	form := forms.NewRecordVerificationRequest(api.app, collection)
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data.", "details": err.Error()})
		return
	}

	if err := form.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while validating the form.", "details": err.Error()})
		return
	}

	event := new(core.RecordRequestVerificationEvent)
	event.HttpContext = c
	event.Collection = collection

	submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeRequestVerificationRequest().Trigger(event, func(e *core.RecordRequestVerificationEvent) error {
				// run in background because we don't need to show the result to the client
				routine.FireAndForget(func() {
					if err := next(e.Record); err != nil {
						api.app.Logger().Debug("Failed to send verification email", "error", err.Error())
					}
				})

				return api.app.OnRecordAfterRequestVerificationRequest().Trigger(event, func(e *core.RecordRequestVerificationEvent) error {
					if e.HttpContext.Writer.Written() {
						return nil
					}

					e.HttpContext.Writer.WriteHeader(http.StatusNoContent)
					return nil
				})
			})
		}
	})

	// eagerly write 204 response and skip submit errors
	// as a measure against users enumeration
	if !c.Writer.Written() {
		c.Status(http.StatusNoContent)
	}

	c.JSON(http.StatusOK, submitErr)
}

func (api *recordAuthApi) confirmVerification(c *gin.Context) {
	collectionValue, exists := c.Get(ContextCollectionKey)
	collection, _ := collectionValue.(*models.Collection)
	if !exists || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	form := forms.NewRecordVerificationConfirm(api.app, collection)
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data.", "details": err.Error()})
		return
	}

	event := new(core.RecordConfirmVerificationEvent)
	event.HttpContext = c
	event.Collection = collection

	_, submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeConfirmVerificationRequest().Trigger(event, func(e *core.RecordConfirmVerificationEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("An error occurred while submitting the form.", err)
				}

				return api.app.OnRecordAfterConfirmVerificationRequest().Trigger(event, func(e *core.RecordConfirmVerificationEvent) error {
					if e.HttpContext.Writer.Written() {
						return nil
					}

					e.HttpContext.Writer.WriteHeader(http.StatusNoContent)
					return nil
				})
			})
		}
	})

	c.JSON(http.StatusOK, submitErr)
}

func (api *recordAuthApi) requestEmailChange(c *gin.Context) {
	collectionValue, exists := c.Get(ContextCollectionKey)
	collection, _ := collectionValue.(*models.Collection)
	if !exists || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	recordValue, exists := c.Get(ContextAuthRecordKey)
	record, _ := recordValue.(*models.Record)
	if !exists || record == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "The request requires valid auth record."})
		return
	}

	form := forms.NewRecordEmailChangeRequest(api.app, record)
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data.", "details": err.Error()})
		return
	}

	event := new(core.RecordRequestEmailChangeEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Record = record

	submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			return api.app.OnRecordBeforeRequestEmailChangeRequest().Trigger(event, func(e *core.RecordRequestEmailChangeEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("Failed to request email change.", err)
				}

				return api.app.OnRecordAfterRequestEmailChangeRequest().Trigger(event, func(e *core.RecordRequestEmailChangeEvent) error {
					if e.HttpContext.Writer.Written() {
						return nil
					}

					e.HttpContext.Writer.WriteHeader(http.StatusNoContent)
					return nil
				})
			})
		}
	})

	c.JSON(http.StatusOK, submitErr)
}

func (api *recordAuthApi) confirmEmailChange(c *gin.Context) {
	collectionValue, exists := c.Get(ContextCollectionKey)
	collection, _ := collectionValue.(*models.Collection)
	if !exists || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	form := forms.NewRecordEmailChangeConfirm(api.app, collection)
	if err := c.ShouldBind(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data.", "details": err.Error()})
		return
	}

	event := new(core.RecordConfirmEmailChangeEvent)
	event.HttpContext = c
	event.Collection = collection

	_, submitErr := form.Submit(func(next forms.InterceptorNextFunc[*models.Record]) forms.InterceptorNextFunc[*models.Record] {
		return func(record *models.Record) error {
			event.Record = record

			return api.app.OnRecordBeforeConfirmEmailChangeRequest().Trigger(event, func(e *core.RecordConfirmEmailChangeEvent) error {
				if err := next(e.Record); err != nil {
					return NewBadRequestError("Failed to confirm email change.", err)
				}

				return api.app.OnRecordAfterConfirmEmailChangeRequest().Trigger(event, func(e *core.RecordConfirmEmailChangeEvent) error {
					if e.HttpContext.Writer.Written() {
						return nil
					}

					e.HttpContext.Writer.WriteHeader(http.StatusNoContent)
					return nil
				})
			})
		}
	})

	c.JSON(http.StatusOK, submitErr)
}

func (api *recordAuthApi) listExternalAuths(c *gin.Context) {
	collectionValue, exists := c.Get(ContextCollectionKey)
	collection, _ := collectionValue.(*models.Collection)
	if !exists || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing record ID."})
		return
	}

	record, err := api.app.Dao().FindRecordById(collection.Id, id)
	if err != nil || record == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found."})
		return
	}

	externalAuths, err := api.app.Dao().FindAllExternalAuthsByRecord(record)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to fetch the external auths for the specified auth record.", "details": err.Error()})
		return
	}

	event := new(core.RecordListExternalAuthsEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Record = record
	event.ExternalAuths = externalAuths

	api.app.OnRecordListExternalAuthsRequest().Trigger(event, func(e *core.RecordListExternalAuthsEvent) error {
		c.JSON(http.StatusOK, e.ExternalAuths)
		return nil
	})
}

func (api *recordAuthApi) unlinkExternalAuth(c *gin.Context) {
	collectionValue, exists := c.Get(ContextCollectionKey)
	collection, _ := collectionValue.(*models.Collection)
	if !exists || collection == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing collection context."})
		return
	}

	id := c.Param("id")
	provider := c.Param("provider")
	if id == "" || provider == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing record ID or provider."})
		return
	}

	record, err := api.app.Dao().FindRecordById(collection.Id, id)
	if err != nil || record == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found."})
		return
	}

	externalAuth, err := api.app.Dao().FindExternalAuthByRecordAndProvider(record, provider)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Missing external auth provider relation.", "details": err.Error()})
		return
	}

	event := new(core.RecordUnlinkExternalAuthEvent)
	event.HttpContext = c
	event.Collection = collection
	event.Record = record
	event.ExternalAuth = externalAuth

	api.app.OnRecordBeforeUnlinkExternalAuthRequest().Trigger(event, func(e *core.RecordUnlinkExternalAuthEvent) error {
		if err := api.app.Dao().DeleteExternalAuth(externalAuth); err != nil {
			return NewBadRequestError("Cannot unlink the external auth provider.", err)
		}

		return api.app.OnRecordAfterUnlinkExternalAuthRequest().Trigger(event, func(e *core.RecordUnlinkExternalAuthEvent) error {
			if e.HttpContext.Writer.Written() {
				return nil
			}

			e.HttpContext.Writer.WriteHeader(http.StatusNoContent)
			return nil
		})
	})
}

// -------------------------------------------------------------------

const (
	oauth2SubscriptionTopic   string = "@oauth2"
	oauth2RedirectFailurePath string = "../_/#/auth/oauth2-redirect-failure"
	oauth2RedirectSuccessPath string = "../_/#/auth/oauth2-redirect-success"
)

type oauth2RedirectData struct {
	State string `form:"state" query:"state" json:"state"`
	Code  string `form:"code" query:"code" json:"code"`
	Error string `form:"error" query:"error" json:"error,omitempty"`
}

func (api *recordAuthApi) oauth2SubscriptionRedirect(c *gin.Context) {
	redirectStatusCode := http.StatusTemporaryRedirect
	if c.Request.Method != http.MethodGet {
		redirectStatusCode = http.StatusSeeOther
	}

	data := oauth2RedirectData{}
	if err := c.ShouldBind(&data); err != nil {
		api.app.Logger().Debug("Failed to read OAuth2 redirect data", "error", err)
		c.Redirect(redirectStatusCode, oauth2RedirectFailurePath)
		return
	}

	if data.State == "" {
		api.app.Logger().Debug("Missing OAuth2 state parameter")
		c.Redirect(redirectStatusCode, oauth2RedirectFailurePath)
		return
	}

	client, err := api.app.SubscriptionsBroker().ClientById(data.State)
	if err != nil || client.IsDiscarded() || !client.HasSubscription(oauth2SubscriptionTopic) {
		api.app.Logger().Debug("Missing or invalid OAuth2 subscription client", "error", err, "clientId", data.State)
		c.Redirect(redirectStatusCode, oauth2RedirectFailurePath)
		return
	}
	defer client.Unsubscribe(oauth2SubscriptionTopic)

	encodedData, err := json.Marshal(data)
	if err != nil {
		api.app.Logger().Debug("Failed to marshalize OAuth2 redirect data", "error", err)
		c.Redirect(redirectStatusCode, oauth2RedirectFailurePath)
		return
	}

	msg := subscriptions.Message{
		Name: oauth2SubscriptionTopic,
		Data: encodedData,
	}

	client.Send(msg)

	if data.Error != "" || data.Code == "" {
		api.app.Logger().Debug("Failed OAuth2 redirect due to an error or missing code parameter", "error", data.Error, "clientId", data.State)
		c.Redirect(redirectStatusCode, oauth2RedirectFailurePath)
		return
	}

	c.Redirect(redirectStatusCode, oauth2RedirectSuccessPath)
}
