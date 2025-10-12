package models

import "time"

type User struct {
	ID            uint64           `json:"id,string"`
	CreatedAt     *time.Time       `json:"createdAt"`
	UpdatedAt     *time.Time       `json:"updatedAt"`
	Username      string           `json:"username"`
	Alias         *string          `json:"alias,omitempty"`
	Email         *string          `json:"email,omitempty"`
	VersionCheck  string           `json:"-"`
	PasswordHash  string           `json:"-"`
	IsAdmin       bool             `json:"isAdmin"`
	NotifyByEmail bool             `json:"notifyByEmail"`
	Permissions   []UserPermission `json:"permissions"`
	CreatedBy     *uint64          `json:"createdBy,string,omitempty"`
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

type FileAccessInfo struct {
	Username     string     `json:"username"`
	Alias        *string    `json:"alias,omitempty"`
	LastViewedAt *time.Time `json:"lastViewedAt"`
}

type FileInfo struct {
	Key          string           `json:"key"`
	URL          string           `json:"url,omitempty"`
	CreatedAt    *time.Time       `json:"createdAt,omitempty"`
	AccessType   string           `json:"accessType,omitempty"` // "read_only", "read_and_download"
	LastViewedAt *time.Time       `json:"lastViewedAt,omitempty"`
	AccessList   []FileAccessInfo `json:"accessList,omitempty"`
}

type ListFilesResponse struct {
	Path    string     `json:"path"`
	Folders []string   `json:"folders"`
	Files   []FileInfo `json:"files"`
}

type CreateUserRequest struct {
	Username        string `json:"username" binding:"required"`
	Password        string `json:"password" binding:"required"`
	Alias           string `json:"alias"`
	Email           string `json:"email"`
	IsAdmin         bool   `json:"is_admin"`
	NotifyByEmail   bool   `json:"notifyByEmail"`
	SendAuthByEmail bool   `json:"sendAuthByEmail"`
}

type AssignPermissionRequest struct {
	UserID       uint64 `json:"user_id,string" binding:"required"`
	FolderPrefix string `json:"folder_prefix" binding:"required"`
}

type ResetPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

type UpdateAdminRequest struct {
	Username string  `json:"username"`
	Password string  `json:"password"`
	Email    *string `json:"email"`
}

type UpdateUserNotifyRequest struct {
	NotifyByEmail bool `json:"notifyByEmail"`
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

type DeleteItemsRequest struct {
	Keys    []string `json:"keys"`
	Folders []string `json:"folders"`
}

type MoveItemsRequest struct {
	Sources     []string `json:"sources" binding:"required"`
	Destination string   `json:"destination" binding:"required"`
}
