package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerPort        string
	YDBEndpoint       string
	YDBDatabasePath   string
	JWTSecretKey      string
	S3Endpoint        string
	S3Region          string
	S3BucketName      string
	S3AccessKeyID     string
	S3SecretAccessKey string
	AdminUser         string
	AdminPassword     string
	OriginURL         string
	PresignTTLSeconds int
}

func Load() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	return &Config{
		ServerPort:        getEnv("SERVER_PORT", "8080"),
		YDBEndpoint:       getEnv("YDB_ENDPOINT", ""),
		YDBDatabasePath:   getEnv("YDB_DATABASE_PATH", ""),
		JWTSecretKey:      getEnv("JWT_SECRET_KEY", ""),
		S3Endpoint:        getEnv("S3_ENDPOINT", "https://storage.yandexcloud.net"),
		S3Region:          getEnv("S3_REGION", "ru-central1"),
		S3BucketName:      getEnv("S3_BUCKET_NAME", ""),
		S3AccessKeyID:     getEnv("S3_ACCESS_KEY_ID", ""),
		S3SecretAccessKey: getEnv("S3_SECRET_ACCESS_KEY", ""),
		AdminUser:         getEnv("ADMIN_USER", "admin"),
		AdminPassword:     getEnv("ADMIN_PASSWORD", ""),
		OriginURL:         getEnv("ORIGIN_URL", "http://localhost:8080"),
		PresignTTLSeconds: getEnvInt("PRESIGN_TTL_SECONDS", 45, 10, 3600),
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
