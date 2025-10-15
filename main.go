package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/marketconnect/bfe-sl/api"
	"github.com/marketconnect/bfe-sl/config"
	"github.com/marketconnect/bfe-sl/db"
	"github.com/marketconnect/bfe-sl/email"
	"github.com/marketconnect/bfe-sl/models"
	"github.com/marketconnect/bfe-sl/s3"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/ydb-platform/ydb-go-sdk/v3/table"
)

var (
	router *gin.Engine
)

func init() {
	ctx := context.Background()
	cfg := config.Load()

	ydbDriver, err := db.InitYDB(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to connect to YDB: %v", err)
	}

	store := &db.YdbStore{Driver: ydbDriver}

	s3Client := s3.NewClient(cfg)
	emailClient := email.NewClient(cfg)

	seedAdminUser(ctx, store, cfg)

	handler := &api.Handler{
		Store:                store,
		S3Client:             s3Client,
		EmailClient:          emailClient,
		JwtSecret:            cfg.JWTSecretKey,
		PreSignTTL:           time.Duration(cfg.PresignTTLSeconds) * time.Second,
		PreSignTTLForArchive: time.Duration(cfg.PreSignTTLForArchive) * time.Second,
		PdfToImagesFuncName:  cfg.PdfToImagesFuncName,
	}

	router = gin.New()

	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	router.SetTrustedProxies(nil)

	corsConfig := cors.Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}

	origins := strings.Split(cfg.OriginURL, ",")
	for i := range origins {
		origins[i] = strings.TrimRight(strings.TrimSpace(origins[i]), "/")
	}
	corsConfig.AllowOriginFunc = func(origin string) bool {
		o := strings.TrimRight(origin, "/")
		for _, allowed := range origins {
			if o == allowed {
				return true
			}
			u1, err1 := url.Parse(o)
			u2, err2 := url.Parse(allowed)
			if err1 == nil && err2 == nil && u1.Host == u2.Host {
				return true
			}
		}
		return false
	}

	router.Use(cors.New(corsConfig))

	apiV1 := router.Group("/api/v1")
	{
		authGroup := apiV1.Group("/auth")
		authGroup.POST("/login", handler.LoginHandler)
		authGroup.OPTIONS("/login", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		authedRoutes := apiV1.Group("/")
		authedRoutes.Use(api.AuthMiddleware(cfg.JWTSecretKey))
		{
			authedRoutes.GET("/files", handler.ListFilesHandler)
			authedRoutes.POST("/files/generate-upload-url", handler.GenerateUploadURLHandler)
			authedRoutes.POST("/archive", handler.DownloadArchiveHandler)
			authedRoutes.GET("/files/presign", handler.PresignFileHandler)

			adminRoutes := authedRoutes.Group("/admin")
			adminRoutes.Use(api.AdminMiddleware())
			{
				adminRoutes.PUT("/self", handler.UpdateAdminSelfHandler)
				adminRoutes.GET("/users", handler.ListUsersHandler)
				adminRoutes.POST("/users", handler.CreateUserHandler)
				adminRoutes.DELETE("/users/:id", handler.DeleteUserHandler)
				adminRoutes.POST("/users/:id/password", handler.ResetUserPasswordHandler)
				adminRoutes.PUT("/users/:id", handler.UpdateUserNotifyHandler)
				adminRoutes.POST("/permissions", handler.AssignPermissionHandler)
				adminRoutes.DELETE("/permissions/:id", handler.RevokePermissionHandler)
				adminRoutes.GET("/storage/folders", handler.ListAllFoldersHandler)
				adminRoutes.POST("/storage/folders", handler.CreateFolderHandler)
				adminRoutes.POST("/storage/move", handler.MoveStorageItemsHandler)
				adminRoutes.POST("/storage/copy", handler.CopyStorageItemsHandler)
				adminRoutes.DELETE("/storage/items", handler.DeleteStorageItemsHandler)
				adminRoutes.PUT("/storage/permissions", handler.SetPermissionsHandler)
			}
		}
	}
}

func Handler(w http.ResponseWriter, r *http.Request) {
	router.ServeHTTP(w, r)
}

func main() {
	port := config.Load().ServerPort
	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func seedAdminUser(ctx context.Context, store db.Store, cfg *config.Config) {
	if cfg.AdminPassword == "" {
		log.Println("ADMIN_PASSWORD is not set, skipping admin user seeding.")
		return
	}

	// Check if a user with the admin username already exists.
	existingUser, err := store.GetUserByUsername(ctx, cfg.AdminUser)
	if err != nil && err != db.ErrNotFound {
		log.Fatalf("Failed to check for admin user by username: %v", err)
	}

	// If a user with that name exists...
	if existingUser != nil {
		// ...and it's our super admin (ID=1), then our job is done.
		if existingUser.ID == 1 {
			log.Println("Super admin user (ID=1) with the correct username already exists.")
			return
		}
		// ...but it's some other user, this is a critical conflict.
		log.Fatalf("FATAL: A user with the admin username '%s' already exists but is not ID=1.", cfg.AdminUser)
	}
	// Now, check if ID=1 is taken by someone else (edge case).
	userByID, err := store.GetUserByID(ctx, 1)
	if err != nil && err != db.ErrNotFound {
		log.Fatalf("Failed to check for user with ID=1: %v", err)
	}
	if userByID != nil {
		log.Fatalf("FATAL: A user with ID=1 already exists but has a different username ('%s').", userByID.Username)
	}

	log.Println("Super admin user not found, creating...")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash admin password: %v", err)
	}

	admin := &models.User{ID: 1, Username: cfg.AdminUser, PasswordHash: string(hashedPassword), IsAdmin: true, Alias: nil}
	if err := store.CreateUser(ctx, admin); err != nil {
		log.Fatalf("Failed to create admin user: %v", err)
	}
	log.Printf("Admin user '%s' created successfully.", cfg.AdminUser)
}
