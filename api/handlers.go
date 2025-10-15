package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/marketconnect/bfe-sl/auth"
	"github.com/marketconnect/bfe-sl/db"
	"github.com/marketconnect/bfe-sl/email"
	"github.com/marketconnect/bfe-sl/models"
	"github.com/marketconnect/bfe-sl/s3"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	Store                db.Store
	S3Client             *s3.Client
	EmailClient          *email.Client
	JwtSecret            string
	PreSignTTL           time.Duration
	PreSignTTLForArchive time.Duration
	PdfToImagesFuncName  string
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

	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	// Super admin (ID=1) can create admins.
	// Regular admins can only create regular users.
	if adminID != 1 && req.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "only super admin can create other admins"})
		return
	}

	// Check for username uniqueness
	existingUser, err := h.Store.GetUserByUsername(c.Request.Context(), req.Username)
	if err != nil && err != db.ErrNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error while checking username"})
		return
	}
	if existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "username is already taken"})
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

	var emailPtr *string
	if req.Email != "" {
		emailPtr = &req.Email
	}

	user := &models.User{
		Username:      req.Username,
		Alias:         aliasPtr,
		Email:         emailPtr,
		PasswordHash:  string(hashedPassword),
		IsAdmin:       req.IsAdmin,
		NotifyByEmail: req.NotifyByEmail,
		CreatedBy:     &adminID,
	}

	if err := h.Store.CreateUser(c.Request.Context(), user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user", "details": err.Error()})
		return
	}

	if user.IsAdmin {
		folderPath := fmt.Sprintf("%d/", user.ID)

		if err := h.S3Client.CreateFolder(folderPath); err != nil {
			log.Printf("CRITICAL: User %d created, but failed to create S3 folder '%s': %v. Manual intervention required.", user.ID, folderPath, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user created, but failed to create s3 folder", "details": err.Error()})
			return
		}
		perm := &models.UserPermission{
			UserID:       user.ID,
			FolderPrefix: &folderPath,
		}

		if err := h.Store.AssignPermission(c.Request.Context(), perm); err != nil {
			log.Printf("CRITICAL: User %d and folder '%s' created, but failed to assign permission: %v. Manual intervention required.", user.ID, folderPath, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user and folder created, but failed to assign permission", "details": err.Error()})
			return
		}
	}

	if req.SendAuthByEmail && req.Email != "" {
		err := h.EmailClient.SendAuthDetails(c.Request.Context(), req.Email, req.Username, req.Password)
		if err != nil {
			log.Printf("WARN: User %d created successfully, but failed to send auth email to %s: %v", user.ID, req.Email, err)
		}
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

	if req.Email != nil {
		if *req.Email == "" {
			adminUser.Email = nil
		} else {
			adminUser.Email = req.Email
		}
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

	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	// Super admin can reset anyone's password.
	// Regular admins can only reset passwords of users they created.
	if adminID != 1 {
		userToReset, err := h.Store.GetUserByID(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve user to reset password", "details": err.Error()})
			return
		}
		if userToReset.CreatedBy == nil || *userToReset.CreatedBy != adminID {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied: you can only reset passwords for users you created"})
			return
		}
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

	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)
	folderPath := req.FolderPath
	// Super admin can create folders anywhere.
	// Regular admins can only create folders inside their own root folder.
	if adminID != 1 {
		adminRootFolder := fmt.Sprintf("%d/", adminID)
		if !strings.HasPrefix(folderPath, adminRootFolder) {
			// Disallow absolute paths from regular admins.
			if strings.HasPrefix(folderPath, "/") {
				c.JSON(http.StatusForbidden, gin.H{"error": "access denied: you can only create folders inside your own root folder"})
				return
			}
			// Prepend the admin's root folder to the path.
			folderPath = adminRootFolder + folderPath
		}
	}

	if err := h.S3Client.CreateFolder(folderPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create folder", "details": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "folder created successfully"})
}

func (h *Handler) DeleteStorageItemsHandler(c *gin.Context) {
	var req models.DeleteItemsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	// --- Authorization Check ---
	if adminID != 1 {
		adminRootFolder := fmt.Sprintf("%d/", adminID)
		for _, key := range req.Keys {
			if !strings.HasPrefix(key, adminRootFolder) {
				c.JSON(http.StatusForbidden, gin.H{"error": "access denied: you can only delete items inside your own root folder", "item": key})
				return
			}
		}
		for _, folder := range req.Folders {
			if !strings.HasPrefix(folder, adminRootFolder) {
				c.JSON(http.StatusForbidden, gin.H{"error": "access denied: you can only delete items inside your own root folder", "item": folder})
				return
			}
		}
	}
	// --- End Authorization Check ---

	keysToDelete := make(map[string]struct{})

	for _, key := range req.Keys {
		keysToDelete[key] = struct{}{}
	}

	for _, folder := range req.Folders {
		if !strings.HasSuffix(folder, "/") {
			folder += "/"
		}

		objects, err := h.S3Client.ListAllObjects(folder)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list objects in folder for deletion", "folder": folder, "details": err.Error()})
			return
		}
		for _, objKey := range objects {
			keysToDelete[objKey] = struct{}{}
		}
		keysToDelete[folder] = struct{}{}
	}

	var keySlice []string
	for k := range keysToDelete {
		keySlice = append(keySlice, k)
	}

	if err := h.S3Client.DeleteObjects(keySlice); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete one or more items from storage", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "items deleted successfully"})
}

func (h *Handler) MoveStorageItemsHandler(c *gin.Context) {
	var req models.MoveItemsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	// Ensure destination is a folder
	if !strings.HasSuffix(req.Destination, "/") {
		req.Destination += "/"
	}

	// --- Authorization Check ---
	if adminID != 1 {
		adminRootFolder := fmt.Sprintf("%d/", adminID)
		if !strings.HasPrefix(req.Destination, adminRootFolder) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied: destination is outside your root folder"})
			return
		}
		for _, source := range req.Sources {
			if !strings.HasPrefix(source, adminRootFolder) {
				c.JSON(http.StatusForbidden, gin.H{"error": "access denied: you can only move items from your own root folder", "item": source})
				return
			}
		}
	}
	// --- End Authorization Check ---

	objectMoves := make(map[string]string)
	var keysToDelete []string

	for _, source := range req.Sources {
		isFolder := strings.HasSuffix(source, "/")
		baseName := path.Base(source)
		if isFolder {
			baseName += "/"
		}

		// Determine non-conflicting destination name
		finalDestPath := req.Destination + baseName
		if isFolder {
			exists, err := h.S3Client.PrefixExists(finalDestPath)
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "failed to check for existing folder", "details": err.Error()})
				return
			}
			if exists {
				base := strings.TrimSuffix(baseName, "/")
				found := false
				for i := 1; i <= 1000; i++ { // Limit to 1000 attempts
					newName := fmt.Sprintf("%s (%d)/", base, i)
					newPrefix := req.Destination + newName
					exists, err := h.S3Client.PrefixExists(newPrefix)
					if err != nil {
						c.JSON(http.StatusBadGateway, gin.H{"error": "failed to check for existing folder", "details": err.Error()})
						return
					}
					if !exists {
						finalDestPath = newPrefix
						found = true
						break
					}
				}
				if !found {
					c.JSON(http.StatusConflict, gin.H{"error": "could not find a unique name for folder", "folder": baseName})
					return
				}
			}
		} else {
			exists, err := h.S3Client.ObjectExists(finalDestPath)
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "failed to check for existing file", "details": err.Error()})
				return
			}
			if exists {
				ext := filepath.Ext(baseName)
				base := strings.TrimSuffix(baseName, ext)
				found := false
				for i := 1; i <= 1000; i++ { // Limit to 1000 attempts
					newName := fmt.Sprintf("%s (%d)%s", base, i, ext)
					newKey := req.Destination + newName
					exists, err := h.S3Client.ObjectExists(newKey)
					if err != nil {
						c.JSON(http.StatusBadGateway, gin.H{"error": "failed to check for existing file", "details": err.Error()})
						return
					}
					if !exists {
						finalDestPath = newKey
						found = true
						break
					}
				}
				if !found {
					c.JSON(http.StatusConflict, gin.H{"error": "could not find a unique name for file", "file": baseName})
					return
				}
			}
		}

		if isFolder {
			objects, err := h.S3Client.ListAllKeysUnderPrefix(source)
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list objects in folder for moving", "folder": source, "details": err.Error()})
				return
			}
			for _, objKey := range objects {
				relativePath := strings.TrimPrefix(objKey, source)
				destKey := finalDestPath + relativePath
				objectMoves[objKey] = destKey
			}
		} else { // is a file
			objectMoves[source] = finalDestPath
		}
	}

	for source, dest := range objectMoves {
		if err := h.S3Client.CopyObject(source, dest); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to copy object during move", "source": source, "destination": dest, "details": err.Error()})
			return
		}
		keysToDelete = append(keysToDelete, source)
	}

	if err := h.S3Client.DeleteObjects(keysToDelete); err != nil {
		log.Printf("CRITICAL: Failed to delete source objects after move. Manual cleanup required. Keys: %v. Error: %v", keysToDelete, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "items copied, but failed to delete original items. please contact support.", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Items moved successfully"})
}

func (h *Handler) CopyStorageItemsHandler(c *gin.Context) {
	var req models.MoveItemsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	// Ensure destination is a folder
	if !strings.HasSuffix(req.Destination, "/") {
		req.Destination += "/"
	}

	// --- Authorization Check ---
	if adminID != 1 {
		adminRootFolder := fmt.Sprintf("%d/", adminID)
		if !strings.HasPrefix(req.Destination, adminRootFolder) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied: destination is outside your root folder"})
			return
		}
		for _, source := range req.Sources {
			if !strings.HasPrefix(source, adminRootFolder) {
				c.JSON(http.StatusForbidden, gin.H{"error": "access denied: you can only copy items from your own root folder", "item": source})
				return
			}
		}
	}
	// --- End Authorization Check ---

	objectCopies := make(map[string]string)

	for _, source := range req.Sources {
		isFolder := strings.HasSuffix(source, "/")
		baseName := path.Base(source)
		if isFolder {
			baseName += "/"
		}

		// Determine non-conflicting destination name
		finalDestPath := req.Destination + baseName
		if isFolder {
			exists, err := h.S3Client.PrefixExists(finalDestPath)
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "failed to check for existing folder", "details": err.Error()})
				return
			}
			if exists {
				base := strings.TrimSuffix(baseName, "/")
				found := false
				for i := 1; i <= 1000; i++ { // Limit to 1000 attempts
					newName := fmt.Sprintf("%s (%d)/", base, i)
					newPrefix := req.Destination + newName
					exists, err := h.S3Client.PrefixExists(newPrefix)
					if err != nil {
						c.JSON(http.StatusBadGateway, gin.H{"error": "failed to check for existing folder", "details": err.Error()})
						return
					}
					if !exists {
						finalDestPath = newPrefix
						found = true
						break
					}
				}
				if !found {
					c.JSON(http.StatusConflict, gin.H{"error": "could not find a unique name for folder", "folder": baseName})
					return
				}
			}
		} else {
			exists, err := h.S3Client.ObjectExists(finalDestPath)
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "failed to check for existing file", "details": err.Error()})
				return
			}
			if exists {
				ext := filepath.Ext(baseName)
				base := strings.TrimSuffix(baseName, ext)
				found := false
				for i := 1; i <= 1000; i++ { // Limit to 1000 attempts
					newName := fmt.Sprintf("%s (%d)%s", base, i, ext)
					newKey := req.Destination + newName
					exists, err := h.S3Client.ObjectExists(newKey)
					if err != nil {
						c.JSON(http.StatusBadGateway, gin.H{"error": "failed to check for existing file", "details": err.Error()})
						return
					}
					if !exists {
						finalDestPath = newKey
						found = true
						break
					}
				}
				if !found {
					c.JSON(http.StatusConflict, gin.H{"error": "could not find a unique name for file", "file": baseName})
					return
				}
			}
		}

		if isFolder {
			objects, err := h.S3Client.ListAllKeysUnderPrefix(source)
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list objects in folder for copying", "folder": source, "details": err.Error()})
				return
			}
			for _, objKey := range objects {
				relativePath := strings.TrimPrefix(objKey, source)
				destKey := finalDestPath + relativePath
				objectCopies[objKey] = destKey
			}
		} else { // is a file
			objectCopies[source] = finalDestPath
		}
	}

	for source, dest := range objectCopies {
		if err := h.S3Client.CopyObject(source, dest); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to copy object", "source": source, "destination": dest, "details": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Items copied successfully"})
}

func (h *Handler) SetPermissionsHandler(c *gin.Context) {
	var req models.SetPermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	permissionsToSet := make(map[string]string)

	// --- Authorization and Path Expansion ---
	adminRootFolder := fmt.Sprintf("%d/", adminID)
	for _, p := range req.Paths {
		// Regular admins can only set permissions within their own root folder.
		if adminID != 1 {
			if !strings.HasPrefix(p, adminRootFolder) {
				c.JSON(http.StatusForbidden, gin.H{"error": "access denied: you can only set permissions for items inside your own root folder", "item": p})
				return
			}
		}

		if strings.HasSuffix(p, "/") { // It's a folder
			// We set the permission on the folder itself for hierarchical lookups for future files
			permissionsToSet[p] = req.AccessType

			// And on all files currently within it, as requested
			files, err := h.S3Client.ListAllObjects(p)
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list objects in folder", "folder": p, "details": err.Error()})
				return
			}
			for _, fileKey := range files {
				permissionsToSet[fileKey] = req.AccessType
			}
		} else { // It's a file
			permissionsToSet[p] = req.AccessType
		}
	}

	if err := h.Store.UpsertFilePermissions(c.Request.Context(), permissionsToSet); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to set permissions in database", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "success"})
}

func (h *Handler) ListUsersHandler(c *gin.Context) {
	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	users, err := h.Store.GetAllUsers(c.Request.Context(), adminID)
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

	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	userToDelete, err := h.Store.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		if err == db.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve user to delete", "details": err.Error()})
		return
	}

	// Super admin can delete anyone.
	// Regular admins can only delete users they created.
	if adminID != 1 {
		if userToDelete.CreatedBy == nil || *userToDelete.CreatedBy != adminID {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied: you can only delete users you created"})
			return
		}
	}

	// If the user is an admin, attempt to delete their S3 folder first.
	if userToDelete.IsAdmin {
		adminRootFolder := fmt.Sprintf("%d/", userToDelete.ID)
		keysToDelete, err := h.S3Client.ListAllKeysUnderPrefix(adminRootFolder)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list objects in admin's folder for deletion", "folder": adminRootFolder, "details": err.Error()})
			return
		}

		if len(keysToDelete) > 0 {
			if err := h.S3Client.DeleteObjects(keysToDelete); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete admin's folder from storage", "details": err.Error()})
				return
			}
		}
	}

	if err := h.Store.DeleteUser(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user deleted successfully"})
}

func (h *Handler) UpdateUserNotifyHandler(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	var req models.UpdateUserNotifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	if userID == adminID {
		c.JSON(http.StatusForbidden, gin.H{"error": "you cannot change your own notification settings"})
		return
	}

	userToUpdate, err := h.Store.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve user", "details": err.Error()})
		return
	}
	if userToUpdate.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "you cannot change notification settings for another admin"})
		return
	}

	if err := h.Store.UpdateUserNotifyByEmail(c.Request.Context(), userID, req.NotifyByEmail, req.Email); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user notification setting", "details": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "user notification setting updated successfully"})
}

func (h *Handler) AssignPermissionHandler(c *gin.Context) {
	var req models.AssignPermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	// Super admin can assign any permission.
	// Regular admins can only assign permissions to users they created, and only for subfolders of their own root folder.
	if adminID != 1 {
		// Check if target user was created by this admin
		targetUser, err := h.Store.GetUserByID(c.Request.Context(), req.UserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve target user", "details": err.Error()})
			return
		}
		if targetUser.CreatedBy == nil || *targetUser.CreatedBy != adminID {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied: you can only assign permissions to users you created"})
			return
		}

		// Check if folder is within admin's root folder
		adminRootFolder := fmt.Sprintf("%d/", adminID)
		if !strings.HasPrefix(req.FolderPrefix, adminRootFolder) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied: you can only assign permissions to subfolders of your own root folder"})
			return
		}
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
	adminIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	adminID := adminIDVal.(uint64)

	folders, err := h.S3Client.ListAllFolders()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list folders from storage service", "details": err.Error()})
		return
	}

	// Super admin sees all folders.
	// Regular admins see only folders inside their own root folder.
	if adminID != 1 {
		adminRootFolder := fmt.Sprintf("%d/", adminID)
		var adminFolders []string
		for _, folder := range folders {
			if strings.HasPrefix(folder, adminRootFolder) {
				adminFolders = append(adminFolders, folder)
			}
		}
		folders = adminFolders
	}

	c.JSON(http.StatusOK, gin.H{"folders": folders})
}

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
		c.JSON(http.StatusOK, models.ListFilesResponse{
			Path:    "/",
			Folders: []string{},
			Files:   []models.FileInfo{},
		})
		return
	}

	isAdminVal, _ := c.Get("isAdmin")
	isAdmin := isAdminVal.(bool)

	requestedPath := c.Query("path")
	if requestedPath == "" || requestedPath == "/" {
		// Regular admin (not superadmin) sees the content of their own root folder
		if isAdmin && userID != 1 {
			adminRootFolder := fmt.Sprintf("%d/", userID)
			listOutput, err := h.S3Client.ListObjects(adminRootFolder, "/")
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "failed to list files from storage service", "details": err.Error()})
				return
			}

			// --- Enrich files with metadata ---
			fileKeys := make([]string, 0, len(listOutput.Files))
			pathsToCheckSet := make(map[string]struct{})
			for _, file := range listOutput.Files {
				fileKeys = append(fileKeys, file.Key)
				pathsToCheckSet[file.Key] = struct{}{}
				currentPath := file.Key
				for {
					currentPath = path.Dir(currentPath)
					if currentPath == "." || currentPath == "/" {
						break
					}
					folderPath := currentPath + "/"
					if _, exists := pathsToCheckSet[folderPath]; !exists {
						pathsToCheckSet[folderPath] = struct{}{}
					}
				}
			}
			pathsToCheck := make([]string, 0, len(pathsToCheckSet))
			for p := range pathsToCheckSet {
				pathsToCheck = append(pathsToCheck, p)
			}

			filePerms, err := h.Store.GetFilePermissions(c.Request.Context(), pathsToCheck)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve file permissions", "details": err.Error()})
				return
			}
			viewTimes, err := h.Store.GetLastViewTimes(c.Request.Context(), userID, fileKeys)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve view logs", "details": err.Error()})
				return
			}
			// --- Admin-specific logic to build accessList ---
			var allUsersForAdmin []models.User
			var allPermissionsForUsers map[uint64][]models.UserPermission
			var allViewLogs map[string]map[uint64]time.Time

			if len(fileKeys) > 0 {
				users, err := h.Store.GetAllUsers(c.Request.Context(), userID)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get users for admin", "details": err.Error()})
					return
				}
				allUsersForAdmin = users

				if len(allUsersForAdmin) > 0 {
					userIDs := make([]uint64, 0, len(allUsersForAdmin))
					for _, u := range allUsersForAdmin {
						userIDs = append(userIDs, u.ID)
					}

					var permsErr, logsErr error
					wg := sync.WaitGroup{}
					wg.Add(2)
					go func() {
						defer wg.Done()
						allPermissionsForUsers, permsErr = h.Store.GetPermissionsForUsers(c.Request.Context(), userIDs)
					}()
					go func() {
						defer wg.Done()
						allViewLogs, logsErr = h.Store.GetViewLogsForUsersAndFiles(c.Request.Context(), userIDs, fileKeys)
					}()
					wg.Wait()

					if permsErr != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get permissions for users", "details": permsErr.Error()})
						return
					}
					if logsErr != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get view logs for users", "details": logsErr.Error()})
						return
					}
				}
			}
			// --- END: Admin-specific logic ---

			files := make([]models.FileInfo, 0, len(listOutput.Files))
			for _, file := range listOutput.Files {
				accessType := "read_and_download" // Default
				if val, ok := filePerms[file.Key]; ok {
					accessType = val
				} else {
					currentPath := file.Key
					for {
						currentPath = path.Dir(currentPath)
						if currentPath == "." || currentPath == "/" {
							break
						}
						folderPath := currentPath + "/"
						if val, ok := filePerms[folderPath]; ok {
							accessType = val
							break
						}
					}
				}

				var lastViewedAt *time.Time
				if vt, ok := viewTimes[file.Key]; ok {
					lastViewedAt = &vt
				}
				createdAt := file.LastModified

				fileInfo := models.FileInfo{
					Key:          file.Key,
					CreatedAt:    &createdAt,
					AccessType:   accessType,
					LastViewedAt: lastViewedAt,
				}

				// --- Populate AccessList ---
				var accessList []models.FileAccessInfo
				for _, user := range allUsersForAdmin {
					userPermissions, ok := allPermissionsForUsers[user.ID]
					if !ok {
						continue
					}

					hasAccess := false
					for _, p := range userPermissions {
						if p.FolderPrefix != nil && strings.HasPrefix(file.Key, *p.FolderPrefix) {
							hasAccess = true
							break
						}
					}

					if hasAccess {
						accessInfo := models.FileAccessInfo{
							Username: user.Username,
							Alias:    user.Alias,
						}
						if fileLogs, ok := allViewLogs[file.Key]; ok {
							if viewTime, ok := fileLogs[user.ID]; ok {
								vt := viewTime
								accessInfo.LastViewedAt = &vt
							}
						}
						accessList = append(accessList, accessInfo)
					}
				}
				fileInfo.AccessList = accessList
				files = append(files, fileInfo)
			}

			c.JSON(http.StatusOK, models.ListFilesResponse{
				Path:    "/", // Path is still root
				Folders: listOutput.Folders,
				Files:   files,
			})
			return
		}

		// Superadmin and regular users see their assigned root folders
		var rootFolders []string
		for _, p := range permissions {
			if p.FolderPrefix != nil {
				rootFolders = append(rootFolders, *p.FolderPrefix)
			}
		}
		c.JSON(http.StatusOK, models.ListFilesResponse{
			Path:    "/",
			Folders: rootFolders,
			Files:   []models.FileInfo{},
		})
		return
	}

	if !strings.HasSuffix(requestedPath, "/") {
		requestedPath += "/"
	}

	isAllowed := false
	for _, p := range permissions {
		if p.FolderPrefix != nil && strings.HasPrefix(requestedPath, *p.FolderPrefix) {
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

	// --- Enrich files with metadata ---

	// 1. Collect all paths for which we need metadata
	fileKeys := make([]string, 0, len(listOutput.Files))
	pathsToCheckSet := make(map[string]struct{})
	for _, file := range listOutput.Files {
		fileKeys = append(fileKeys, file.Key)
		pathsToCheckSet[file.Key] = struct{}{}
		currentPath := file.Key
		for {
			currentPath = path.Dir(currentPath)
			if currentPath == "." || currentPath == "/" {
				break
			}
			folderPath := currentPath + "/"
			if _, exists := pathsToCheckSet[folderPath]; !exists {
				pathsToCheckSet[folderPath] = struct{}{}
			}
		}
	}
	pathsToCheck := make([]string, 0, len(pathsToCheckSet))
	for p := range pathsToCheckSet {
		pathsToCheck = append(pathsToCheck, p)
	}

	// 2. Fetch metadata from DB in parallel
	var filePerms map[string]string
	var viewTimes map[string]time.Time
	var permsErr, viewsErr error
	// --- NEW: Admin-specific variables ---
	var allUsersForAdmin []models.User
	var allPermissionsForUsers map[uint64][]models.UserPermission
	var allViewLogs map[string]map[uint64]time.Time
	var adminDataErr error

	wg := sync.WaitGroup{}
	if len(pathsToCheck) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			filePerms, permsErr = h.Store.GetFilePermissions(c.Request.Context(), pathsToCheck)
		}()
	}
	if len(fileKeys) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			viewTimes, viewsErr = h.Store.GetLastViewTimes(c.Request.Context(), userID, fileKeys)
		}()
		// --- NEW: Admin-specific fetch ---
		if isAdmin {
			wg.Add(1)
			go func() {
				defer wg.Done()
				users, err := h.Store.GetAllUsers(c.Request.Context(), userID)
				if err != nil {
					adminDataErr = fmt.Errorf("failed to get users for admin: %w", err)
					return
				}
				allUsersForAdmin = users

				if len(allUsersForAdmin) == 0 {
					return
				}

				userIDs := make([]uint64, 0, len(allUsersForAdmin))
				for _, u := range allUsersForAdmin {
					userIDs = append(userIDs, u.ID)
				}

				perms, err := h.Store.GetPermissionsForUsers(c.Request.Context(), userIDs)
				if err != nil {
					adminDataErr = fmt.Errorf("failed to get permissions for users: %w", err)
					return
				}
				allPermissionsForUsers = perms

				logs, err := h.Store.GetViewLogsForUsersAndFiles(c.Request.Context(), userIDs, fileKeys)
				if err != nil {
					adminDataErr = fmt.Errorf("failed to get view logs for users: %w", err)
					return
				}
				allViewLogs = logs
			}()
		}
	}
	wg.Wait()

	if permsErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve file permissions", "details": permsErr.Error()})
		return
	}
	if viewsErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve view logs", "details": viewsErr.Error()})
		return
	}
	// --- NEW: Check admin data error ---
	if adminDataErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve admin data for access list", "details": adminDataErr.Error()})
		return
	}

	// 3. Construct response
	files := make([]models.FileInfo, 0, len(listOutput.Files))
	for _, file := range listOutput.Files {
		accessType := "read_and_download" // Default
		if val, ok := filePerms[file.Key]; ok {
			accessType = val
		} else {
			currentPath := file.Key
			for {
				currentPath = path.Dir(currentPath)
				if currentPath == "." || currentPath == "/" {
					break
				}
				folderPath := currentPath + "/"
				if val, ok := filePerms[folderPath]; ok {
					accessType = val
					break
				}
			}
		}

		var lastViewedAt *time.Time
		if vt, ok := viewTimes[file.Key]; ok {
			lastViewedAt = &vt
		}
		createdAt := file.LastModified

		fileInfo := models.FileInfo{
			Key:          file.Key,
			CreatedAt:    &createdAt,
			AccessType:   accessType,
			LastViewedAt: lastViewedAt,
		}

		// --- Populate AccessList ---
		var accessList []models.FileAccessInfo
		for _, user := range allUsersForAdmin {
			userPermissions, ok := allPermissionsForUsers[user.ID]
			if !ok {
				continue
			}

			hasAccess := false
			for _, p := range userPermissions {
				if p.FolderPrefix != nil && strings.HasPrefix(file.Key, *p.FolderPrefix) {
					hasAccess = true
					break
				}
			}

			if hasAccess {
				accessInfo := models.FileAccessInfo{
					Username: user.Username,
					Alias:    user.Alias,
				}
				if fileLogs, ok := allViewLogs[file.Key]; ok {
					if viewTime, ok := fileLogs[user.ID]; ok {
						vt := viewTime
						accessInfo.LastViewedAt = &vt
					}
				}
				accessList = append(accessList, accessInfo)
			}
		}
		fileInfo.AccessList = accessList
		files = append(files, fileInfo)
	}
	// --- End of metadata enrichment ---

	c.JSON(http.StatusOK, models.ListFilesResponse{
		Path:    requestedPath,
		Folders: listOutput.Folders,
		Files:   files,
	})
}

func (h *Handler) GenerateUploadURLHandler(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := userIDVal.(uint64)
	isAdminVal, _ := c.Get("isAdmin")
	isAdmin := isAdminVal.(bool)
	var req models.GenerateUploadURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	// --- Authorization Check ---
	if isAdmin {
		if userID != 1 { // Regular admin logic
			adminRootFolder := fmt.Sprintf("%d/", userID)
			if req.Prefix == "" {
				req.Prefix = adminRootFolder
			} else if !strings.HasPrefix(req.Prefix, adminRootFolder) {
				c.JSON(http.StatusForbidden, gin.H{"error": "access denied to this path"})
				return
			}
		}
		// Super admin (userID == 1) is allowed to proceed with any prefix.
	} else { // Regular user logic
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
			if p.FolderPrefix != nil && strings.HasPrefix(uploadPath, *p.FolderPrefix) {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied to this path"})
			return
		}
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

func (h *Handler) PresignFileHandler(c *gin.Context) {
	userIDVal, ok := c.Get("userID")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := userIDVal.(uint64)
	isAdminVal, _ := c.Get("isAdmin")
	isAdmin := isAdminVal.(bool)

	key := c.Query("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing key"})
		return
	}

	// Проверяем доступ так же, как в ListFilesHandler
	permissions, err := h.Store.GetUserPermissions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve permissions"})
		return
	}
	allowed := false
	for _, p := range permissions {
		if p.FolderPrefix != nil && strings.HasPrefix(key, *p.FolderPrefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	// Log the view action
	if err := h.Store.LogFileView(c.Request.Context(), userID, key); err != nil {
		log.Printf("WARN: Failed to log file view for user %d, key %s: %v", userID, key, err)
		// Do not fail the request, just log the error
	}

	// Check for read-only access for non-admins
	if !isAdmin {
		// Hierarchically check permissions
		pathsToCheck := []string{key}
		currentPath := key
		for {
			currentPath = path.Dir(currentPath)
			if currentPath == "." || currentPath == "/" {
				break
			}
			pathsToCheck = append(pathsToCheck, currentPath+"/")
		}

		perms, err := h.Store.GetFilePermissions(c.Request.Context(), pathsToCheck)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve file permissions", "details": err.Error()})
			return
		}

		accessType := "read_and_download" // Default
		for _, p := range pathsToCheck {
			if val, ok := perms[p]; ok {
				accessType = val
				break // Most specific permission found
			}
		}

		if accessType == "read_only" {
			if !strings.HasSuffix(strings.ToLower(key), ".pdf") {
				c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "read-only view is only supported for PDF files"})
				return
			}

			outputPrefix := path.Join("converted", key) + "/"
			manifestKey := path.Join(outputPrefix, "manifest.json")

			var pageCount int

			// 1. Check for cached manifest
			manifestResp, err := h.S3Client.GetObject(manifestKey)
			if err == nil {
				// Manifest exists, parse it
				log.Printf("Cache hit for converted file %s. Reading manifest.", key)
				body, readErr := io.ReadAll(manifestResp.Body)
				manifestResp.Body.Close()
				if readErr != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read conversion manifest", "details": readErr.Error()})
					return
				}
				var manifest struct {
					PageCount int `json:"page_count"`
				}
				if jsonErr := json.Unmarshal(body, &manifest); jsonErr != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse conversion manifest", "details": jsonErr.Error()})
					return
				}
				pageCount = manifest.PageCount
				log.Printf("Manifest parsed for %s, pages: %d", key, pageCount)
			} else {
				var nsk *types.NoSuchKey
				if errors.As(err, &nsk) {
					// Manifest does not exist, invoke function
					log.Printf("Cache miss for %s, invoking conversion function.", key)

					count, invokeErr := h.invokePdfToImagesFunction(c.Request.Context(), key, outputPrefix)
					if invokeErr != nil {
						log.Printf("ERROR: PDF to images function invocation failed for key %s: %v", key, invokeErr)
						c.JSON(http.StatusBadGateway, gin.H{"error": "failed to process file for viewing", "details": invokeErr.Error()})
						return
					}
					pageCount = count
				} else {
					// Some other S3 error
					log.Printf("ERROR: Failed to check for manifest s3://%s/%s: %v", h.S3Client.BucketName, manifestKey, err)
					c.JSON(http.StatusBadGateway, gin.H{"error": "failed to check for converted file", "details": err.Error()})
					return
				}
			}

			if pageCount <= 0 {
				c.JSON(http.StatusOK, gin.H{"status": "converted", "pages": []string{}})
				return
			}

			// 3. Generate presigned URLs for pages
			urls := make([]string, pageCount)
			errs := make(chan error, pageCount)
			var wg sync.WaitGroup

			for i := 0; i < pageCount; i++ {
				wg.Add(1)
				go func(pageNum int) {
					defer wg.Done()
					imageKey := path.Join(outputPrefix, fmt.Sprintf("page-%d.webp", pageNum+1))
					url, err := h.S3Client.GeneratePresignedURL(imageKey, h.PreSignTTL)
					if err != nil {
						errs <- fmt.Errorf("failed to sign url for page %d: %w", pageNum+1, err)
						return
					}
					urls[pageNum] = url
				}(i)
			}
			wg.Wait()
			close(errs)

			if len(errs) > 0 {
				firstErr := <-errs
				log.Printf("ERROR: Failed to generate one or more presigned URLs for converted file %s: %v", key, firstErr)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate URLs for file pages", "details": firstErr.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"status": "converted", "pages": urls})
			return
		}
	}

	u, err := h.S3Client.GeneratePresignedURL(key, h.PreSignTTL)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to presign url", "details": err.Error()})
		return
	}

	// Отдаём JSON {"url": "..."} (фронт завернёт через /s3proxy)
	c.JSON(http.StatusOK, gin.H{"url": u})
}

type iamToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

var (
	cachedToken     string
	tokenExpiration time.Time
	tokenMutex      sync.Mutex
)

func (h *Handler) getIAMToken(ctx context.Context) (string, error) {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	if cachedToken != "" && time.Now().Before(tokenExpiration) {
		return cachedToken, nil
	}

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create metadata request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get IAM token from metadata service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("metadata service returned status %d: %s", resp.StatusCode, string(body))
	}

	var token iamToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return "", fmt.Errorf("failed to decode IAM token: %w", err)
	}

	cachedToken = token.AccessToken
	tokenExpiration = time.Now().Add(time.Duration(token.ExpiresIn-60) * time.Second)

	return cachedToken, nil
}

type pdfConversionRequest struct {
	PdfKey       string `json:"pdf_key"`
	OutputPrefix string `json:"output_prefix"`
}

type pdfConversionResponse struct {
	Status    string `json:"status"`
	PageCount int    `json:"page_count"`
	Format    string `json:"format"`
	Message   string `json:"message"`
}

func (h *Handler) invokePdfToImagesFunction(ctx context.Context, pdfKey, outputPrefix string) (int, error) {
	if h.PdfToImagesFuncName == "" {
		return 0, errors.New("PDF to images function name is not configured")
	}

	iamToken, err := h.getIAMToken(ctx)
	if err != nil {
		return 0, fmt.Errorf("could not get IAM token for function invocation: %w", err)
	}

	payload := pdfConversionRequest{
		PdfKey:       pdfKey,
		OutputPrefix: outputPrefix,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal function payload: %w", err)
	}

	client := &http.Client{Timeout: 45 * time.Second}
	url := fmt.Sprintf("https://functions.yandexcloud.net/%s", h.PdfToImagesFuncName)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payloadBytes))
	if err != nil {
		return 0, fmt.Errorf("failed to create function invocation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+iamToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("function invocation failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read function response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("function returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
	}

	var convResp pdfConversionResponse

	var ycResponse struct {
		StatusCode int    `json:"statusCode"`
		Body       string `json:"body"`
	}
	if err := json.Unmarshal(body, &ycResponse); err == nil && ycResponse.StatusCode != 0 {
		if ycResponse.StatusCode >= 300 {
			return 0, fmt.Errorf("function returned error status %d in body: %s", ycResponse.StatusCode, ycResponse.Body)
		}
		if err := json.Unmarshal([]byte(ycResponse.Body), &convResp); err != nil {
			return 0, fmt.Errorf("failed to unmarshal nested function response body: %w. Body was: %s", err, ycResponse.Body)
		}
	} else {
		if err := json.Unmarshal(body, &convResp); err != nil {
			return 0, fmt.Errorf("failed to unmarshal function response: %w. Body was: %s", err, string(body))
		}
	}

	if convResp.Status != "success" {
		return 0, fmt.Errorf("conversion function reported failure: %s", convResp.Message)
	}

	return convResp.PageCount, nil
}

func (h *Handler) DownloadArchiveHandler(c *gin.Context) {

	// Authenticate user
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := userIDVal.(uint64)

	isAdminVal, _ := c.Get("isAdmin")
	isAdmin := isAdminVal.(bool)

	// Parse request body
	var req models.ArchiveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Get user permissions
	permissions, err := h.Store.GetUserPermissions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve permissions"})
		return
	}

	// define a function to check if a path is allowed
	isAllowed := func(path string) bool {
		for _, p := range permissions {
			if p.FolderPrefix != nil && strings.HasPrefix(path, *p.FolderPrefix) {
				return true
			}
		}
		return false
	}

	// Collect a unique list of all file keys from all requested directories and files
	allKeys := make(map[string]struct{})

	// Check permissions for individual files and add them to the list allKeys
	for _, key := range req.Keys {
		if !isAllowed(key) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied to file: " + key})
			return
		}
		allKeys[key] = struct{}{}
	}

	// Check permissions for folders and add all files from them to the list allKeys
	for _, folder := range req.Folders {
		if !isAllowed(folder) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied to folder: " + folder})
			return
		}
		filesInFolder, err := h.S3Client.ListAllObjects(folder)
		if err != nil {
			log.Printf("Error listing objects for prefix %s: %v", folder, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list files in folder", "details": err.Error()})
			return
		}
		for _, file := range filesInFolder {
			allKeys[file] = struct{}{}
		}
	}

	finalKeys := make([]string, 0, len(allKeys))

	// if a user is not an admin and there are files to check
	// then we need to check permissions for each file since any of them can be a read-only file
	if !isAdmin && len(allKeys) > 0 {
		// ---> Step 1: Collect all paths for checking (files + all their parent folders)
		pathsToCheck := make(map[string]struct{})
		for key := range allKeys {
			pathsToCheck[key] = struct{}{}
			currentPath := key
			// Go up the directory hierarchy
			for {
				// path.Dir removes the last element. "a/b/c.txt" -> "a/b"
				parent := path.Dir(currentPath)
				if parent == "." || parent == "/" || parent == "" {
					break
				}
				// add a slash to the end to match the folder storage format
				folderPath := parent + "/"
				pathsToCheck[folderPath] = struct{}{}
				currentPath = parent
				log.Printf("DEBUG: Checking folder %s for access\n", folderPath)
			}
		}
		// Convert the map to a slice for the database query
		keysToCheckSlice := make([]string, 0, len(pathsToCheck))
		for p := range pathsToCheck {
			keysToCheckSlice = append(keysToCheckSlice, p)
		}
		// ---> Step 2: Make one database query
		filePerms, err := h.Store.GetFilePermissions(c.Request.Context(), keysToCheckSlice)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve file permissions", "details": err.Error()})
			return
		}

		// ---> ШАГ 3: Check permissions for each file
		for key := range allKeys {
			isReadOnly := false
			log.Printf("DEBUG: Checking file %s for access\n", key)
			// Check the file itself
			if accessType, ok := filePerms[key]; ok && accessType == "read_only" {
				isReadOnly = true
				log.Printf("DEBUG: File %s is read-only\n", key)
			}

			// Check the parent folders
			if !isReadOnly {
				currentPath := key
				for {
					parent := path.Dir(currentPath)
					if parent == "." || parent == "/" || parent == "" {
						break
					}
					folderPath := parent + "/"
					if accessType, ok := filePerms[folderPath]; ok && accessType == "read_only" {
						isReadOnly = true
						break // Checked the parent folder, no need to check further
					}
					currentPath = parent
				}
			}

			// If no read-only access found, add the file to the final list
			if !isReadOnly {
				finalKeys = append(finalKeys, key)
			}
		}
	} else {
		// Admin can download all files
		for key := range allKeys {
			finalKeys = append(finalKeys, key)
		}
	}

	// ---> Generate presigned URLs for the filtered list of files `finalKeys`
	urls := make(map[string]string)
	for _, key := range finalKeys {
		if err := h.Store.LogFileView(c.Request.Context(), userID, key); err != nil {
			log.Printf("WARN: Failed to log file view for user %d, key %s: %v", userID, key, err)
		}
		url, err := h.S3Client.GeneratePresignedURL(key, h.PreSignTTLForArchive)
		if err != nil {
			log.Printf("Error generating presigned URL for key %s: %v", key, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate URL for a file", "file": key})
			return
		}
		urls[key] = url
	}
	c.JSON(http.StatusOK, models.PresignFilesResponse{URLs: urls})
}
