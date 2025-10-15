package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerPort           string
	YDBEndpoint          string
	YDBDatabasePath      string
	JWTSecretKey         string
	S3Endpoint           string
	S3Region             string
	S3BucketName         string
	S3AccessKeyID        string
	S3SecretAccessKey    string
	AdminUser            string
	AdminPassword        string
	OriginURL            string
	PresignTTLSeconds    int
	PreSignTTLForArchive int
	SESEndpoint          string
	SESRegion            string
	SESAccessKeyID       string
	SESSecretAccessKey   string
	EmailFrom            string
	AppLoginURL          string
	PdfToImagesFuncName  string
}

func Load() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}
	s3Endpoint := getEnv("S3_ENDPOINT", "https://storage.yandexcloud.net")
	// If the env var is set but is an empty string, it will override the default.
	// We must fall back to the default in that case to prevent errors.
	if s3Endpoint == "" {
		s3Endpoint = "https://storage.yandexcloud.net"
	}
	if !strings.HasPrefix(s3Endpoint, "http://") && !strings.HasPrefix(s3Endpoint, "https://") {
		s3Endpoint = "https://" + s3Endpoint
		log.Printf("WARN: S3_ENDPOINT was missing a protocol scheme. Prepending 'https://'. New endpoint: %s", s3Endpoint)
	}

	return &Config{
		ServerPort:           getEnv("SERVER_PORT", "8080"),
		YDBEndpoint:          getEnv("YDB_ENDPOINT", ""),
		YDBDatabasePath:      getEnv("YDB_DATABASE_PATH", ""),
		JWTSecretKey:         getEnv("JWT_SECRET_KEY", ""),
		S3Endpoint:           s3Endpoint,
		S3Region:             getEnv("S3_REGION", "ru-central1"),
		S3BucketName:         getEnv("S3_BUCKET_NAME", ""),
		S3AccessKeyID:        getEnv("S3_ACCESS_KEY_ID", ""),
		S3SecretAccessKey:    getEnv("S3_SECRET_ACCESS_KEY", ""),
		AdminUser:            getEnv("ADMIN_USER", "admin"),
		AdminPassword:        getEnv("ADMIN_PASSWORD", ""),
		OriginURL:            getEnv("ORIGIN_URL", "http://localhost:8080"),
		PresignTTLSeconds:    getEnvInt("PRESIGN_TTL_SECONDS", 45, 10, 3600),
		PreSignTTLForArchive: getEnvInt("PRESIGN_TTL_FOR_ARCHIVE_SECONDS", 60, 10, 3600),
		SESEndpoint:          getEnv("SES_ENDPOINT", "https://email.cloud.yandex.net"),
		SESRegion:            getEnv("SES_REGION", "ru-central1"),
		SESAccessKeyID:       getEnv("SES_ACCESS_KEY_ID", ""),
		SESSecretAccessKey:   getEnv("SES_SECRET_ACCESS_KEY", ""),
		EmailFrom:            getEnv("EMAIL_FROM", ""),
		AppLoginURL:          getEnv("APP_LOGIN_URL", ""),
		PdfToImagesFuncName:  getEnv("PDF_TO_IMAGES_FUNC_NAME", ""),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	if fallback == "" {
		log.Fatalf("FATAL: Environment variable %s is not set.", key)
	}
	return fallback
}

func getEnvInt(key string, fallback, min, max int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			if n < min {
				return min
			}
			if n > max {
				return max
			}
			return n
		}
		log.Printf("WARN: %s=%q is not an integer, using default %d", key, v, fallback)
	}

	if fallback < min {
		return min
	}
	if fallback > max {
		return max
	}
	return fallback
}
