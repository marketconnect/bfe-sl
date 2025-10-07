package models

import "time"

type User struct {
	ID           uint64           `json:"id,string"`
	CreatedAt    *time.Time       `json:"createdAt"`
	UpdatedAt    *time.Time       `json:"updatedAt"`
	Username     string           `json:"username"`
	Alias        *string          `json:"alias,omitempty"`
	VersionCheck string           `json:"-"`
	PasswordHash string           `json:"-"`
	IsAdmin      bool             `json:"isAdmin"`
	Permissions  []UserPermission `json:"permissions"`
}

type UserPermission struct {
	ID           uint64     `json:"id,string"`
	CreatedAt    *time.Time `json:"createdAt"`
	UpdatedAt    *time.Time `json:"updatedAt"`
	UserID       uint64     `json:"userId,string"`
	FolderPrefix *string    `json:"folderPrefix"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type FileWithURL struct {
	Key string `json:"key"`
	URL string `json:"url"`
}

type ListFilesResponse struct {
	Path    string        `json:"path"`
	Folders []string      `json:"folders"`
	Files   []FileWithURL `json:"files"`
}

type CreateUserRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Alias    string `json:"alias"`
	IsAdmin  bool   `json:"is_admin"`
}

type AssignPermissionRequest struct {
	UserID       uint64 `json:"user_id,string" binding:"required"`
	FolderPrefix string `json:"folder_prefix" binding:"required"`
}

type ResetPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

type UpdateAdminRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ArchiveRequest struct {
	Keys    []string `json:"keys"`
	Folders []string `json:"folders"`
}

type CreateFolderRequest struct {
	FolderPath string `json:"folderPath" binding:"required"`
}

type GenerateUploadURLRequest struct {
	FileName    string `json:"fileName" binding:"required"`
	ContentType string `json:"contentType" binding:"required"`
	Prefix      string `json:"prefix"`
}

type GenerateUploadURLResponse struct {
	UploadURL string `json:"uploadUrl"`
	ObjectKey string `json:"objectKey"`
}

type ArchiveJob struct {
	ID           uint64    `json:"id,string"`
	UserID       uint64    `json:"userId,string"`
	Status       string    `json:"status"` // PENDING, PROCESSING, COMPLETED, FAILED
	ArchiveKey   *string   `json:"archiveKey,omitempty"`
	ErrorMessage *string   `json:"errorMessage,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type RequestArchiveResponse struct {
	JobID  uint64 `json:"jobId,string"`
	Status string `json:"status"`
}

type GetArchiveStatusResponse struct {
	JobID       uint64 `json:"jobId,string"`
	Status      string `json:"status"`
	DownloadURL string `json:"downloadUrl,omitempty"`
	Error       string `json:"error,omitempty"`
}
