package apis

import (
	"context"
	"net/http"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/forms"
	"github.com/pocketbase/pocketbase/models"
	"github.com/pocketbase/pocketbase/tools/filesystem"
	"github.com/pocketbase/pocketbase/tools/rest"
	"github.com/pocketbase/pocketbase/tools/types"
	"github.com/spf13/cast"
)

// bindBackupApi registers the file api endpoints and the corresponding handlers.
//
// @todo add hooks once the app hooks api restructuring is finalized
func bindBackupApi(app core.App, api *gin.RouterGroup) {
	backupApi := backupApi{app: app}

	backups := api.Group("/backups")
	backups.Use(ActivityLogger(app))
	backups.GET("", RequireAdminAuth(), backupApi.list)
	backups.POST("", RequireAdminAuth(), backupApi.create)
	backups.POST("/upload", RequireAdminAuth(), backupApi.upload)
	backups.GET("/:key", backupApi.download)
	backups.DELETE("/:key", RequireAdminAuth(), backupApi.delete)
	backups.POST("/:key/restore", RequireAdminAuth(), backupApi.restore)

}

type backupApi struct {
	app core.App
}

func (api *backupApi) list(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fsys, err := api.app.NewBackupsFilesystem()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to load backups filesystem."})
		return
	}
	defer fsys.Close()

	fsys.SetContext(ctx)

	backups, err := fsys.List("")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to retrieve backup items. Raw error: " + err.Error()})
		return
	}

	result := make([]models.BackupFileInfo, len(backups))

	for i, obj := range backups {
		modified, _ := types.ParseDateTime(obj.ModTime)

		result[i] = models.BackupFileInfo{
			Key:      obj.Key,
			Size:     obj.Size,
			Modified: modified,
		}
	}

	c.JSON(http.StatusOK, result)
}

func (api *backupApi) create(c *gin.Context) {
	if api.app.Store().Has(core.StoreKeyActiveBackup) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Try again later - another backup/restore process has already been started"})
		return
	}

	form := forms.NewBackupCreate(api.app)
	if err := c.ShouldBindJSON(form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "An error occurred while loading the submitted data."})
		return
	}

	form.Submit(func(next forms.InterceptorNextFunc[string]) forms.InterceptorNextFunc[string] {
		return func(name string) error {
			if err := next(name); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create backup."})
				return err
			}

			c.Status(http.StatusNoContent)
			return nil
		}
	})
}

func (api *backupApi) upload(c *gin.Context) {
	files, err := rest.FindUploadedFiles(c.Request, "file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing or invalid uploaded file."})
		return
	}

	form := forms.NewBackupUpload(api.app)
	form.File = files[0]

	form.Submit(func(next forms.InterceptorNextFunc[*filesystem.File]) forms.InterceptorNextFunc[*filesystem.File] {
		return func(file *filesystem.File) error {
			if err := next(file); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to upload backup."})
				return err
			}

			c.Status(http.StatusNoContent)
			return nil
		}
	})
}

func (api *backupApi) download(c *gin.Context) {
	fileToken := c.Query("token")

	_, err := api.app.Dao().FindAdminByToken(
		fileToken,
		api.app.Settings().AdminFileToken.Secret,
	)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to access the resource."})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fsys, err := api.app.NewBackupsFilesystem()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to load backups filesystem."})
		return
	}
	defer fsys.Close()

	fsys.SetContext(ctx)

	key := c.Param("key")

	br, err := fsys.GetFile(key)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to retrieve backup item. Raw error: " + err.Error()})
		return
	}
	defer br.Close()

	fsys.Serve(
		c.Writer,
		c.Request,
		key,
		filepath.Base(key), // without the path prefix (if any)
	)
}

func (api *backupApi) restore(c *gin.Context) {
	if api.app.Store().Has(core.StoreKeyActiveBackup) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Try again later - another backup/restore process has already been started."})
		return
	}

	key := c.Param("key")

	existsCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fsys, err := api.app.NewBackupsFilesystem()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to load backups filesystem."})
		return
	}
	defer fsys.Close()

	fsys.SetContext(existsCtx)

	if exists, _ := fsys.Exists(key); !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing or invalid backup file."})
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		time.Sleep(1 * time.Second)

		if err := api.app.RestoreBackup(ctx, key); err != nil {
			api.app.Logger().Error("Failed to restore backup", "key", key, "error", err.Error())
		}
	}()

	c.Status(http.StatusNoContent)
}

func (api *backupApi) delete(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fsys, err := api.app.NewBackupsFilesystem()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to load backups filesystem."})
		return
	}
	defer fsys.Close()

	fsys.SetContext(ctx)

	key := c.Param("key")

	if key != "" && cast.ToString(api.app.Store().Get(core.StoreKeyActiveBackup)) == key {
		c.JSON(http.StatusBadRequest, gin.H{"error": "The backup is currently being used and cannot be deleted."})
		return
	}

	if err := fsys.Delete(key); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or already deleted backup file. Raw error: " + err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}
