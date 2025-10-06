module github.com/marketconnect/bfe-sl

// go 1.23

require (
    github.com/aws/aws-sdk-go-v2 v1.26.1
    github.com/aws/aws-sdk-go-v2/config v1.27.11
    github.com/aws/aws-sdk-go-v2/credentials v1.17.11
    github.com/aws/aws-sdk-go-v2/service/s3 v1.53.1
    github.com/gin-contrib/cors v1.7.2
    github.com/gin-gonic/gin v1.9.1
    github.com/golang-jwt/jwt/v5 v5.2.0
    github.com/joho/godotenv v1.5.1
    github.com/ydb-platform/ydb-go-sdk/v3 v3.55.1
    github.com/ydb-platform/ydb-go-yc v0.12.3
    golang.org/x/crypto v0.17.0
    golang.org/x/sys v0.17.0 // Important crypto v0.17.0
)


replace golang.org/x/crypto => golang.org/x/crypto v0.17.0