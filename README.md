# BFE-SL File Management Service

## Overview

This service provides a secure file management solution with a hierarchical user role system. It is designed to be deployed as a serverless function (e.g., Yandex Cloud Function).

The core features include:
-   **User Authentication:** JWT-based authentication for secure access.
-   **Role-Based Access Control (RBAC):**
    -   A single **Super Admin** (ID=1) with full control over the system.
    -   **Admins** who can manage users they create and the files within their own designated folders.
    -   **Regular Users** with access only to the specific folders granted to them by an admin.
-   **File & Folder Management:** Users can list, upload, and download files from their permitted S3 storage locations.
-   **Hierarchical Permissions:** Admins can only create folders and assign permissions within their own root directory.

## API Documentation

The complete API specification is available in the [openapi.yaml](./openapi.yaml) file. This document details all available endpoints, request/response schemas, and authentication requirements.

## Getting Started

### Prerequisites

The service configuration is managed through environment variables. Create a `.env` file in the root of the project with the following variables:

```env
# Server Configuration
SERVER_PORT=8080

# Yandex Database (YDB)
YDB_ENDPOINT=grpcs://ydb.serverless.yandexcloud.net:2135
YDB_DATABASE_PATH=/ru-central1/b1g.../etn...

# JWT Authentication
JWT_SECRET_KEY="your-super-secret-jwt-key"

# Yandex S3 Storage
S3_ENDPOINT=https://storage.yandexcloud.net
S3_REGION=ru-central1
S3_BUCKET_NAME="your-s3-bucket-name"
S3_ACCESS_KEY_ID="your-s3-access-key"
S3_SECRET_ACCESS_KEY="your-s3-secret-key"

# Initial Super Admin User
ADMIN_USER="admin"
ADMIN_PASSWORD="your-secure-initial-admin-password"

# CORS Configuration
ORIGIN_URL="http://localhost:3000,https://your-frontend-domain.com"

# Presigned URL Time-to-Live
PRESIGN_TTL_SECONDS=300


Curl Example:
```
curl -X POST   -H "Content-Type: application/json"   -H "Authorization: Bearer $TOKEN"   -d '{"username": "testuser", "password": "password123", "is_admin": false}'   "$GATEWAY_URL/api/v1/admin/users"

export USER_ID=15101886788856559465

curl -X POST   -H "Content-Type: application/json"   -H "Authorization: Bearer $TOKEN"   -d '{"user_id": '$USER_ID', "folder_prefix": "test-folder/"}'   "$GATEWAY_URL/api/v1/admin/permissions"

TESTUSER_TOKEN=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "password123"}' \
  "$GATEWAY_URL/api/v1/auth/login" | jq -r .token)

echo "Токен для testuser: $TESTUSER_TOKEN"


UPLOAD_DATA=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TESTUSER_TOKEN" \
  -d '{"fileName": "example.txt", "contentType": "text/plain", "prefix": "test-folder/"}' \
  "$GATEWAY_URL/api/v1/files/generate-upload-url")

echo "Ответ от API:"

echo $UPLOAD_DATA

UPLOAD_URL=$(echo $UPLOAD_DATA | jq -r .uploadUrl)

OBJECT_KEY=$(echo $UPLOAD_DATA | jq -r .objectKey)


echo "Hello, Yandex Cloud!" > example.txt


curl -X PUT   -H "Content-Type: text/plain"   --data-binary "@example.txt"   "$UPLOAD_URL"
```

git fetch origin
git switch -c feature-login origin/master
git add -A
git commit -m "Добавляет форму логина"
git switch master
git pull origin master
git merge --no-ff feature-login
git push origin master
