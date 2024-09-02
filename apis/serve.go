package apis

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/migrations"
	"github.com/pocketbase/pocketbase/migrations/logs"
	"github.com/pocketbase/pocketbase/tools/list"
	"github.com/pocketbase/pocketbase/tools/migrate"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// ServeConfig defines a configuration struct for apis.Serve().
type ServeConfig struct {
	ShowStartBanner    bool
	HttpAddr           string
	HttpsAddr          string
	CertificateDomains []string
	AllowedOrigins     []string
}

// Serve starts a new app web server.
func Serve(app core.App, config ServeConfig) (*http.Server, error) {
	if len(config.AllowedOrigins) == 0 {
		config.AllowedOrigins = []string{"*"}
	}

	// ensure that the latest migrations are applied before starting the server
	if err := runMigrations(app); err != nil {
		return nil, err
	}

	// reload app settings in case a new default value was set with a migration
	if err := app.RefreshSettings(); err != nil {
		color.Yellow("=====================================")
		color.Yellow("WARNING: Settings load error! \n%v", err)
		color.Yellow("Fallback to the application defaults.")
		color.Yellow("=====================================")
	}

	router := gin.Default()

	// configure cors
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", strings.Join(config.AllowedOrigins, ","))
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	// start http server
	mainAddr := config.HttpAddr
	if config.HttpsAddr != "" {
		mainAddr = config.HttpsAddr
	}

	var wwwRedirects []string

	// extract the host names for the certificate host policy
	hostNames := config.CertificateDomains
	if len(hostNames) == 0 {
		host, _, _ := net.SplitHostPort(mainAddr)
		hostNames = append(hostNames, host)
	}
	for _, host := range hostNames {
		if strings.HasPrefix(host, "www.") {
			continue // explicitly set www host
		}

		wwwHost := "www." + host
		if !list.ExistInSlice(wwwHost, hostNames) {
			hostNames = append(hostNames, wwwHost)
			wwwRedirects = append(wwwRedirects, wwwHost)
		}
	}

	// implicit www->non-www redirect(s)
	if len(wwwRedirects) > 0 {
		router.Use(func(c *gin.Context) {
			host := c.Request.Host
			if strings.HasPrefix(host, "www.") && list.ExistInSlice(host, wwwRedirects) {
				c.Redirect(http.StatusTemporaryRedirect, "https://"+host[4:]+c.Request.RequestURI)
				c.Abort()
				return
			}
			c.Next()
		})
	}

	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(filepath.Join(app.DataDir(), ".autocert_cache")),
		HostPolicy: autocert.HostWhitelist(hostNames...),
	}

	// base request context used for cancelling long running requests
	baseCtx, cancelBaseCtx := context.WithCancel(context.Background())
	defer cancelBaseCtx()

	server := &http.Server{
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certManager.GetCertificate,
			NextProtos:     []string{acme.ALPNProto},
		},
		ReadTimeout:       10 * time.Minute,
		ReadHeaderTimeout: 30 * time.Second,
		Handler:           router,
		Addr:              mainAddr,
		BaseContext: func(l net.Listener) context.Context {
			return baseCtx
		},
	}

	serveEvent := &core.ServeEvent{
		App:         app,
		Router:      router,
		Server:      server,
		CertManager: certManager,
	}
	if err := app.OnBeforeServe().Trigger(serveEvent); err != nil {
		return nil, err
	}

	if config.ShowStartBanner {
		schema := "http"
		addr := server.Addr

		if config.HttpsAddr != "" {
			schema = "https"

			if len(config.CertificateDomains) > 0 {
				addr = config.CertificateDomains[0]
			}
		}

		date := new(strings.Builder)
		log.New(date, "", log.LstdFlags).Print()

		bold := color.New(color.Bold).Add(color.FgGreen)
		bold.Printf(
			"%s Server started at %s\n",
			strings.TrimSpace(date.String()),
			color.CyanString("%s://%s", schema, addr),
		)

		regular := color.New()
		regular.Printf("├─ REST API: %s\n", color.CyanString("%s://%s/api/", schema, addr))
		regular.Printf("└─ Admin UI: %s\n", color.CyanString("%s://%s/_/", schema, addr))
	}

	var wg sync.WaitGroup

	// try to gracefully shutdown the server on app termination
	app.OnTerminate().Add(func(e *core.TerminateEvent) error {
		cancelBaseCtx()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		wg.Add(1)
		server.Shutdown(ctx)
		if e.IsRestart {
			time.AfterFunc(5*time.Second, func() {
				wg.Done()
			})
		} else {
			wg.Done()
		}

		return nil
	})

	defer wg.Wait()

	// start HTTPS server
	if config.HttpsAddr != "" {
		if config.HttpAddr != "" {
			go http.ListenAndServe(config.HttpAddr, certManager.HTTPHandler(nil))
		}

		return server, server.ListenAndServeTLS("", "")
	}

	// OR start HTTP server
	return server, server.ListenAndServe()
}

type migrationsConnection struct {
	DB             *dbx.DB
	MigrationsList migrate.MigrationsList
}

func runMigrations(app core.App) error {
	connections := []migrationsConnection{
		{
			DB:             app.DB(),
			MigrationsList: migrations.AppMigrations,
		},
		{
			DB:             app.LogsDB(),
			MigrationsList: logs.LogsMigrations,
		},
	}

	for _, c := range connections {
		runner, err := migrate.NewRunner(c.DB, c.MigrationsList)
		if err != nil {
			return err
		}

		if _, err := runner.Up(); err != nil {
			return err
		}
	}

	return nil
}
