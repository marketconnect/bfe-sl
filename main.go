package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/marketconnect/bfe-sl/api"
	"github.com/marketconnect/bfe-sl/config"
	"github.com/marketconnect/bfe-sl/db"
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

	seedAdminUser(ctx, store, cfg)

	handler := &api.Handler{
		Store:     store,
		S3Client:  s3Client,
		JwtSecret: cfg.JWTSecretKey,
	}

	router = gin.Default()

	router.SetTrustedProxies(nil)

	corsConfig := cors.DefaultConfig()

	corsConfig.AllowOrigins = []string{cfg.OriginURL}

	corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Authorization"}
	router.Use(cors.New(corsConfig))

	apiV1 := router.Group("/api/v1")
	{
		authGroup := apiV1.Group("/auth")
		authGroup.POST("/login", handler.LoginHandler)

		authedRoutes := apiV1.Group("/")
		authedRoutes.Use(api.AuthMiddleware(cfg.JWTSecretKey))
		{
			authedRoutes.GET("/files", handler.ListFilesHandler)
			authedRoutes.POST("/files/generate-upload-url", handler.GenerateUploadURLHandler)
			authedRoutes.GET("/archive/status/:jobId", handler.GetArchiveStatusHandler)

			adminRoutes := authedRoutes.Group("/admin")
			adminRoutes.Use(api.AdminMiddleware())
			{
				adminRoutes.PUT("/self", handler.UpdateAdminSelfHandler)
				adminRoutes.GET("/users", handler.ListUsersHandler)
				adminRoutes.POST("/users", handler.CreateUserHandler)
				adminRoutes.DELETE("/users/:id", handler.DeleteUserHandler)
				adminRoutes.POST("/users/:id/password", handler.ResetUserPasswordHandler)
				adminRoutes.POST("/permissions", handler.AssignPermissionHandler)
				adminRoutes.DELETE("/permissions/:id", handler.RevokePermissionHandler)
				adminRoutes.GET("/storage/folders", handler.ListAllFoldersHandler)
				adminRoutes.POST("/storage/folders", handler.CreateFolderHandler)
			}
		}
	}
}

// Handler - это точка входа для Yandex Cloud Function.
// Все HTTP-запросы, поступающие от API Gateway, будут попадать сюда.
func Handler(w http.ResponseWriter, r *http.Request) {
	router.ServeHTTP(w, r)
}

// Эта функция main останется для удобства локального тестирования.
// В среде Yandex Cloud Functions она вызываться не будет.
func main() {
	log.Println("Starting local server for development on :8080")
	// ИСПРАВЛЕНИЕ: Оборачиваем Handler в http.HandlerFunc
	if err := http.ListenAndServe(":8080", http.HandlerFunc(Handler)); err != nil {
		log.Fatalf("Failed to run local server: %v", err)
	}
}

func seedAdminUser(ctx context.Context, store db.Store, cfg *config.Config) {
	if cfg.AdminPassword == "" {
		log.Println("ADMIN_PASSWORD is not set, skipping admin user seeding.")
		return
	}

	_, err := store.GetUserByUsername(ctx, cfg.AdminUser)
	if err == nil {
		log.Println("Admin user already exists.")
		return
	}

	log.Println("Admin user not found, creating...")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash admin password: %v", err)
	}

	admin := &models.User{Username: cfg.AdminUser, PasswordHash: string(hashedPassword), IsAdmin: true, Alias: nil}
	if err := store.CreateUser(ctx, admin); err != nil {
		log.Fatalf("Failed to create admin user: %v", err)
	}
	log.Printf("Admin user '%s' created successfully.", cfg.AdminUser)
}
