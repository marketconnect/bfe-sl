package api

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marketconnect/bfe-sl/auth"
	"github.com/marketconnect/bfe-sl/db"
	"github.com/marketconnect/bfe-sl/models"
	"github.com/marketconnect/bfe-sl/s3"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	Store     db.Store
	S3Client  *s3.Client
	JwtSecret string
}

// Auth Handlers
func (h *Handler) LoginHandler(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	user, err := h.Store.GetUserByUsername(c.Request.Context(), req.Username)
	if err != nil {
		if err == db.ErrNotFound {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error", "details": err.Error()})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := auth.GenerateToken(user.ID, user.IsAdmin, h.JwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// Admin Handlers
func (h *Handler) CreateUserHandler(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	var aliasPtr *string
	if req.Alias != "" {
		aliasPtr = &req.Alias
	}

	user := &models.User{
		Username:     req.Username,
		Alias:        aliasPtr,
		PasswordHash: string(hashedPassword),
		IsAdmin:      req.IsAdmin,
	}

	if err := h.Store.CreateUser(c.Request.Context(), user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user", "details": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "user created successfully", "user_id": user.ID, "password": req.Password})
}

func (h *Handler) UpdateAdminSelfHandler(c *gin.Context) {
	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	var req models.UpdateAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	adminUser, err := h.Store.GetUserByID(c.Request.Context(), adminID)
	if err != nil {
		if err == db.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "admin user not found, please log in again"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not find admin user", "details": err.Error()})
		return
	}

	if req.Username != "" && req.Username != adminUser.Username {
		existingUser, err := h.Store.GetUserByUsername(c.Request.Context(), req.Username)
		if err != nil && err != db.ErrNotFound {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error while checking username"})
			return
		}
		if existingUser != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "username is already taken"})
			return
		}
		adminUser.Username = req.Username
	}

	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
			return
		}
		adminUser.PasswordHash = string(hashedPassword)
	}

	if err := h.Store.UpdateUser(c.Request.Context(), adminUser); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update admin account", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "admin account updated successfully"})
}

func (h *Handler) ResetUserPasswordHandler(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	if err := h.Store.UpdateUserPassword(c.Request.Context(), userID, string(hashedPassword)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password updated successfully", "password": req.Password})
}

func (h *Handler) CreateFolderHandler(c *gin.Context) {
	var req models.CreateFolderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	if err := h.S3Client.CreateFolder(req.FolderPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create folder", "details": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "folder created successfully"})
}

func (h *Handler) ListUsersHandler(c *gin.Context) {
	users, err := h.Store.GetAllUsers(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve users", "details": err.Error()})
		return
	}
	if users == nil {
		users = []models.User{}
	}
	c.JSON(http.StatusOK, users)
}

func (h *Handler) DeleteUserHandler(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	if err := h.Store.DeleteUser(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user deleted successfully"})
}

func (h *Handler) AssignPermissionHandler(c *gin.Context) {
	var req models.AssignPermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	allFolders, err := h.S3Client.ListAllFolders()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to verify folder existence", "details": err.Error()})
		return
	}

	folderExists := false
	for _, folder := range allFolders {
		if folder == req.FolderPrefix {
			folderExists = true
			break
		}
	}

	if !folderExists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Folder does not exist", "details": "Cannot assign permission to a non-existent folder."})
		return
	}

	perm := &models.UserPermission{
		UserID:       req.UserID,
		FolderPrefix: &req.FolderPrefix,
	}

	if err := h.Store.AssignPermission(c.Request.Context(), perm); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not assign permission", "details": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "permission assigned successfully"})
}

func (h *Handler) RevokePermissionHandler(c *gin.Context) {
	permissionIDStr := c.Param("id")
	permissionID, err := strconv.ParseUint(permissionIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid permission ID"})
		return
	}

	if err := h.Store.RevokePermission(c.Request.Context(), uint64(permissionID)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke permission", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "permission revoked successfully"})
}

func (h *Handler) ListAllFoldersHandler(c *gin.Context) {
	folders, err := h.S3Client.ListAllFolders()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list folders from storage service", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"folders": folders})
}

// User Handlers
func (h *Handler) ListFilesHandler(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := userIDVal.(uint64)

	permissions, err := h.Store.GetUserPermissions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve permissions"})
		return
	}

	if len(permissions) == 0 {
		c.JSON(http.StatusOK, models.ListFilesResponse{Path: "/", Folders: []string{}, Files: []models.FileWithURL{}})
		return
	}

	requestedPath := c.Query("path")
	if requestedPath == "" || requestedPath == "/" {
		var rootFolders []string
		for _, p := range permissions {
			rootFolders = append(rootFolders, *p.FolderPrefix)
		}
		c.JSON(http.StatusOK, models.ListFilesResponse{
			Path:    "/",
			Folders: rootFolders,
			Files:   []models.FileWithURL{},
		})
		return
	}

	if !strings.HasSuffix(requestedPath, "/") {
		requestedPath += "/"
	}

	isAllowed := false
	for _, p := range permissions {
		if strings.HasPrefix(requestedPath, *p.FolderPrefix) {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	listOutput, err := h.S3Client.ListObjects(requestedPath, "/")
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list files from storage service", "details": err.Error()})
		return
	}

	var filesWithURLs []models.FileWithURL
	for _, key := range listOutput.Files {
		url, err := h.S3Client.GeneratePresignedURL(key, 1*time.Hour)
		if err != nil {
			log.Printf("Error generating presigned url for key %s: %v", key, err)
			continue
		}
		filesWithURLs = append(filesWithURLs, models.FileWithURL{Key: key, URL: url})
	}

	response := models.ListFilesResponse{
		Path:    requestedPath,
		Folders: listOutput.Folders,
		Files:   filesWithURLs,
	}

	c.JSON(http.StatusOK, response)
}

func (h *Handler) createArchiveAsync(ctx context.Context, job *models.ArchiveJob, req models.ArchiveRequest) {
	// Update job status to PROCESSING
	if err := h.Store.UpdateArchiveJobStatus(ctx, job.ID, "PROCESSING", "", ""); err != nil {
		log.Printf("Failed to update job %d to PROCESSING: %v", job.ID, err)
		return
	}

	// Create the archive
	archiveKey := fmt.Sprintf("archives/%d/%d.zip", job.UserID, job.ID)

	// Create a buffer to hold the zip data
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	allKeys := make(map[string]struct{})

	for _, key := range req.Keys {
		allKeys[key] = struct{}{}
	}

	for _, folderPrefix := range req.Folders {
		files, err := h.S3Client.ListAllObjects(folderPrefix)
		if err != nil {
			log.Printf("Error listing objects for prefix %s: %v", folderPrefix, err)
			continue
		}
		for _, file := range files {
			allKeys[file] = struct{}{}
		}
	}

	for key := range allKeys {
		obj, err := h.S3Client.GetObject(key)
		if err != nil {
			log.Printf("Error getting object %s: %v", key, err)
			continue
		}

		f, err := zipWriter.Create(key)
		if err != nil {
			obj.Body.Close()
			log.Printf("Error creating zip entry for %s: %v", key, err)
			continue
		}

		if _, err := io.Copy(f, obj.Body); err != nil {
			log.Printf("Error copying object body for %s: %v", key, err)
		}
		obj.Body.Close()
	}

	zipWriter.Close()

	// Upload the archive to S3
	if err := h.S3Client.UploadObject(archiveKey, &buf); err != nil {
		log.Printf("Failed to upload archive %s: %v", archiveKey, err)
		if updateErr := h.Store.UpdateArchiveJobStatus(ctx, job.ID, "FAILED", "", err.Error()); updateErr != nil {
			log.Printf("Failed to update job %d to FAILED: %v", job.ID, updateErr)
		}
		return
	}

	// Update job status to COMPLETED
	if err := h.Store.UpdateArchiveJobStatus(ctx, job.ID, "COMPLETED", archiveKey, ""); err != nil {
		log.Printf("Failed to update job %d to COMPLETED: %v", job.ID, err)
	}
}

func (h *Handler) GenerateUploadURLHandler(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := userIDVal.(uint64)

	var req models.GenerateUploadURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	// --- Authorization Check ---
	permissions, err := h.Store.GetUserPermissions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve permissions"})
		return
	}

	uploadPath := req.Prefix
	if !strings.HasSuffix(uploadPath, "/") {
		uploadPath += "/"
	}

	isAllowed := false
	for _, p := range permissions {
		if strings.HasPrefix(uploadPath, *p.FolderPrefix) {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied to this path"})
		return
	}
	// --- End Authorization Check ---

	objectKey := filepath.Join(req.Prefix, req.FileName)
	lifetime := 15 * time.Minute

	url, err := h.S3Client.GeneratePresignedUploadURL(objectKey, lifetime, req.ContentType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate presigned upload URL", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.GenerateUploadURLResponse{
		UploadURL: url,
		ObjectKey: objectKey,
	})
}

func (h *Handler) DownloadArchiveHandler(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := userIDVal.(uint64)

	var req models.ArchiveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	permissions, err := h.Store.GetUserPermissions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve permissions"})
		return
	}

	isAllowed := func(path string) bool {
		for _, p := range permissions {
			if strings.HasPrefix(path, *p.FolderPrefix) {
				return true
			}
		}
		return false
	}

	for _, key := range req.Keys {
		if !isAllowed(key) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied to file: " + key})
			return
		}
	}
	for _, folder := range req.Folders {
		if !isAllowed(folder) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied to folder: " + folder})
			return
		}
	}

	// --- Логика архивации ---
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", "attachment; filename=archive.zip")
	zipWriter := zip.NewWriter(c.Writer)
	defer zipWriter.Close()

	allKeys := make(map[string]struct{})

	for _, key := range req.Keys {
		allKeys[key] = struct{}{}
	}

	for _, folderPrefix := range req.Folders {
		files, err := h.S3Client.ListAllObjects(folderPrefix)
		if err != nil {
			log.Printf("Error listing objects for prefix %s: %v", folderPrefix, err)
			continue
		}
		for _, file := range files {
			allKeys[file] = struct{}{}
		}
	}

	for key := range allKeys {
		obj, err := h.S3Client.GetObject(key)
		if err != nil {
			log.Printf("Error getting object %s: %v", key, err)
			continue
		}

		f, err := zipWriter.Create(key)
		if err != nil {
			obj.Body.Close()
			log.Printf("Error creating zip entry for %s: %v", key, err)
			continue
		}

		if _, err := io.Copy(f, obj.Body); err != nil {
			log.Printf("Error copying object body for %s: %v", key, err)
		}
		obj.Body.Close()
	}
}

func (h *Handler) GetArchiveStatusHandler(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := userIDVal.(uint64)

	jobIDStr := c.Param("jobId")
	jobID, err := strconv.ParseUint(jobIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid job ID"})
		return
	}

	job, err := h.Store.GetArchiveJob(c.Request.Context(), jobID)
	if err != nil {
		if err == db.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "archive job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve job status", "details": err.Error()})
		return
	}

	// Ensure user can only access their own jobs
	if job.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	response := models.GetArchiveStatusResponse{
		JobID:  job.ID,
		Status: job.Status,
		Error:  *job.ErrorMessage,
	}

	if job.Status == "COMPLETED" {
		url, err := h.S3Client.GeneratePresignedURL(*job.ArchiveKey, 1*time.Hour)
		if err != nil {
			log.Printf("Failed to generate presigned URL for completed archive %s: %v", job.ArchiveKey, err)
			// Don't fail the whole request, just omit the URL
		} else {
			response.DownloadURL = url
		}
	}

	c.JSON(http.StatusOK, response)
}
