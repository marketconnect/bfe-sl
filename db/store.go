package db

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/marketconnect/bfe-sl/models"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/table"
	"github.com/ydb-platform/ydb-go-sdk/v3/table/result/named"
	"github.com/ydb-platform/ydb-go-sdk/v3/table/types"
)

var ErrNotFound = errors.New("record not found")

type Store interface {
	CreateUser(ctx context.Context, user *models.User) error
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, userID uint64) error
	GetUserByID(ctx context.Context, userID uint64) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetAllUsers(ctx context.Context) ([]models.User, error)
	AssignPermission(ctx context.Context, permission *models.UserPermission) error
	UpdateUserPassword(ctx context.Context, userID uint64, passwordHash string) error
	RevokePermission(ctx context.Context, permissionID uint64) error
	GetUserPermissions(ctx context.Context, userID uint64) ([]models.UserPermission, error)
	CreateArchiveJob(ctx context.Context, job *models.ArchiveJob) error
	GetArchiveJob(ctx context.Context, jobID uint64) (*models.ArchiveJob, error)
	UpdateArchiveJobStatus(ctx context.Context, jobID uint64, status, archiveKey, errorMessage string) error
}

type YdbStore struct {
	Driver *ydb.Driver
}

func newID() (uint64, error) {
	// Generate a random uint64, this is simple and good enough for this case.
	// For production, consider more robust UUID schemes.
	val, err := rand.Int(rand.Reader, new(big.Int).SetUint64(^uint64(0)))
	if err != nil {
		return 0, err
	}
	return val.Uint64(), nil
}

func (s *YdbStore) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	var found bool

	query := `
		DECLARE $username AS Utf8;
		SELECT id, created_at, updated_at, username, alias, password_hash, is_admin
		FROM users
		WHERE username = $username;
	`
	err := s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$username", types.UTF8Value(username)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			return res.ScanNamed(
				named.Required("id", &user.ID),
				named.Required("created_at", &user.CreatedAt),
				named.Required("updated_at", &user.UpdatedAt),
				named.Required("username", &user.Username),
				named.Optional("alias", &user.Alias),
				named.Required("password_hash", &user.PasswordHash),
				named.Required("is_admin", &user.IsAdmin),
			)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("ydb query failed: %w", err)
	}
	if !found {
		return nil, ErrNotFound
	}

	permissions, err := s.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	user.Permissions = permissions

	return &user, nil
}

func (s *YdbStore) GetUserByID(ctx context.Context, userID uint64) (*models.User, error) {
	var user models.User
	var found bool

	query := `
		DECLARE $id AS Uint64;
		SELECT id, created_at, updated_at, username, alias, password_hash, is_admin
		FROM users
		WHERE id = $id;
	`
	err := s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(userID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			return res.ScanNamed(
				named.Required("id", &user.ID),
				named.Required("created_at", &user.CreatedAt),
				named.Required("updated_at", &user.UpdatedAt),
				named.Required("username", &user.Username),
				named.Optional("alias", &user.Alias),
				named.Required("password_hash", &user.PasswordHash),
				named.Required("is_admin", &user.IsAdmin),
			)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("ydb query failed: %w", err)
	}
	if !found {
		return nil, ErrNotFound
	}

	permissions, err := s.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	user.Permissions = permissions

	return &user, nil
}

func (s *YdbStore) GetUserPermissions(ctx context.Context, userID uint64) ([]models.UserPermission, error) {
	var permissions []models.UserPermission

	query := `
		DECLARE $user_id AS Uint64;
		SELECT id, created_at, updated_at, user_id, folder_prefix
		FROM user_permissions VIEW user_id_index
		WHERE user_id = $user_id;
	`
	err := s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.Uint64Value(userID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var p models.UserPermission
				err = res.ScanNamed(
					named.Required("id", &p.ID),
					named.Required("created_at", &p.CreatedAt),
					named.Required("updated_at", &p.UpdatedAt),
					named.Required("user_id", &p.UserID),
					named.Required("folder_prefix", &p.FolderPrefix),
				)
				if err != nil {
					return err
				}
				permissions = append(permissions, p)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, fmt.Errorf("ydb query failed: %w", err)
	}

	return permissions, nil
}

func (s *YdbStore) CreateUser(ctx context.Context, user *models.User) error {
	id, err := newID()
	if err != nil {
		return err
	}
	user.ID = id
	ts := time.Now()

	query := `
		DECLARE $id AS Uint64;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;
		DECLARE $username AS Utf8;
		DECLARE $alias AS Utf8;
		DECLARE $password_hash AS Utf8;
		DECLARE $is_admin AS Bool;

		UPSERT INTO users (id, created_at, updated_at, username, alias, password_hash, is_admin)
		VALUES ($id, $created_at, $updated_at, $username, $alias, $password_hash, $is_admin);
	`

	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(user.ID)),
				table.ValueParam("$created_at", types.TimestampValue(uint64(ts.UnixMicro()))),
				table.ValueParam("$updated_at", types.TimestampValue(uint64(ts.UnixMicro()))),
				table.ValueParam("$username", types.UTF8Value(user.Username)),
				table.ValueParam("$alias", types.UTF8Value(user.Alias)),
				table.ValueParam("$password_hash", types.UTF8Value(user.PasswordHash)),
				table.ValueParam("$is_admin", types.BoolValue(user.IsAdmin)),
			),
		)
		return err
	})
}

func (s *YdbStore) UpdateUser(ctx context.Context, user *models.User) error {
	user.UpdatedAt = time.Now()

	query := `
		DECLARE $id AS Uint64;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;
		DECLARE $username AS Utf8;
		DECLARE $alias AS Utf8;
		DECLARE $password_hash AS Utf8;
		DECLARE $is_admin AS Bool;

		UPSERT INTO users (id, created_at, updated_at, username, alias, password_hash, is_admin)
		VALUES ($id, $created_at, $updated_at, $username, $alias, $password_hash, $is_admin);
	`
	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(user.ID)),
				table.ValueParam("$created_at", types.TimestampValue(uint64(user.CreatedAt.UnixMicro()))),
				table.ValueParam("$updated_at", types.TimestampValue(uint64(user.UpdatedAt.UnixMicro()))),
				table.ValueParam("$username", types.UTF8Value(user.Username)),
				table.ValueParam("$alias", types.UTF8Value(user.Alias)),
				table.ValueParam("$password_hash", types.UTF8Value(user.PasswordHash)),
				table.ValueParam("$is_admin", types.BoolValue(user.IsAdmin)),
			),
		)
		return err
	})
}

func (s *YdbStore) UpdateUserPassword(ctx context.Context, userID uint64, passwordHash string) error {
	query := `
		DECLARE $id AS Uint64;
		DECLARE $password_hash AS Utf8;
		DECLARE $updated_at AS Timestamp;

		UPDATE users
		SET password_hash = $password_hash, updated_at = $updated_at
		WHERE id = $id;
	`
	ts := time.Now()
	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(userID)),
				table.ValueParam("$password_hash", types.UTF8Value(passwordHash)),
				table.ValueParam("$updated_at", types.TimestampValue(uint64(ts.UnixMicro()))),
			),
		)
		return err
	})
}

func (s *YdbStore) DeleteUser(ctx context.Context, userID uint64) error {
	query := `
		DECLARE $user_id AS Uint64;

		DELETE FROM user_permissions WHERE user_id = $user_id;
		DELETE FROM users WHERE id = $user_id;
	`
	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.SerializableReadWriteTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.Uint64Value(userID)),
			),
		)
		return err
	})
}

func (s *YdbStore) AssignPermission(ctx context.Context, permission *models.UserPermission) error {
	id, err := newID()
	if err != nil {
		return err
	}
	permission.ID = id
	ts := time.Now()

	query := `
		DECLARE $id AS Uint64;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;
		DECLARE $user_id AS Uint64;
		DECLARE $folder_prefix AS Utf8;

		UPSERT INTO user_permissions (id, created_at, updated_at, user_id, folder_prefix)
		VALUES ($id, $created_at, $updated_at, $user_id, $folder_prefix);
	`
	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(permission.ID)),
				table.ValueParam("$created_at", types.TimestampValue(uint64(ts.UnixMicro()))),
				table.ValueParam("$updated_at", types.TimestampValue(uint64(ts.UnixMicro()))),
				table.ValueParam("$user_id", types.Uint64Value(permission.UserID)),
				table.ValueParam("$folder_prefix", types.UTF8Value(permission.FolderPrefix)),
			),
		)
		return err
	})
}

func (s *YdbStore) RevokePermission(ctx context.Context, permissionID uint64) error {
	query := `
		DECLARE $id AS Uint64;
		DELETE FROM user_permissions WHERE id = $id;
	`
	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(permissionID)),
			),
		)
		return err
	})
}

func (s *YdbStore) GetAllUsers(ctx context.Context) ([]models.User, error) {
	// This can be inefficient on large datasets.
	// In a real app, pagination would be required.
	var users []models.User

	query := `
		SELECT id, created_at, updated_at, username, alias, is_admin
		FROM users
		WHERE is_admin = false;
	`
	err := s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query, nil)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var u models.User
				err = res.ScanNamed(
					named.Required("id", &u.ID),
					named.Required("created_at", &u.CreatedAt),
					named.Required("updated_at", &u.UpdatedAt),
					named.Required("username", &u.Username),
					named.Optional("alias", &u.Alias),
					named.Required("is_admin", &u.IsAdmin),
				)
				if err != nil {
					return err
				}
				// This is an N+1 query pattern. For high performance, it would be better
				// to fetch all permissions in a separate query and map them in memory.
				permissions, err := s.GetUserPermissions(ctx, u.ID)
				if err != nil {
					return err
				}
				u.Permissions = permissions
				users = append(users, u)
			}
		}
		return res.Err()
	})

	return users, err
}

func (s *YdbStore) CreateArchiveJob(ctx context.Context, job *models.ArchiveJob) error {
	id, err := newID()
	if err != nil {
		return err
	}
	job.ID = id
	ts := time.Now()
	job.CreatedAt = ts
	job.UpdatedAt = ts

	query := `
		DECLARE $id AS Uint64;
		DECLARE $user_id AS Uint64;
		DECLARE $status AS Utf8;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		UPSERT INTO archive_jobs (id, user_id, status, created_at, updated_at)
		VALUES ($id, $user_id, $status, $created_at, $updated_at);
	`
	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(job.ID)),
				table.ValueParam("$user_id", types.Uint64Value(job.UserID)),
				table.ValueParam("$status", types.UTF8Value(job.Status)),
				table.ValueParam("$created_at", types.TimestampValue(uint64(ts.UnixMicro()))),
				table.ValueParam("$updated_at", types.TimestampValue(uint64(ts.UnixMicro()))),
			),
		)
		return err
	})
}

func (s *YdbStore) GetArchiveJob(ctx context.Context, jobID uint64) (*models.ArchiveJob, error) {
	var job models.ArchiveJob
	var found bool

	query := `
		DECLARE $id AS Uint64;
		SELECT id, user_id, status, archive_key, error_message, created_at, updated_at
		FROM archive_jobs
		WHERE id = $id;
	`
	err := s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(jobID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			return res.ScanNamed(
				named.Required("id", &job.ID),
				named.Required("user_id", &job.UserID),
				named.Required("status", &job.Status),
				named.Optional("archive_key", &job.ArchiveKey),
				named.Optional("error_message", &job.ErrorMessage),
				named.Required("created_at", &job.CreatedAt),
				named.Required("updated_at", &job.UpdatedAt),
			)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("ydb query failed: %w", err)
	}
	if !found {
		return nil, ErrNotFound
	}
	return &job, nil
}

func (s *YdbStore) UpdateArchiveJobStatus(ctx context.Context, jobID uint64, status, archiveKey, errorMessage string) error {
	ts := time.Now()
	query := `
		DECLARE $id AS Uint64;
		DECLARE $status AS Utf8;
		DECLARE $archive_key AS Utf8;
		DECLARE $error_message AS Utf8;
		DECLARE $updated_at AS Timestamp;

		UPDATE archive_jobs
		SET status = $status, archive_key = $archive_key, error_message = $error_message, updated_at = $updated_at
		WHERE id = $id;
	`
	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(jobID)),
				table.ValueParam("$status", types.UTF8Value(status)),
				table.ValueParam("$archive_key", types.UTF8Value(archiveKey)),
				table.ValueParam("$error_message", types.UTF8Value(errorMessage)),
				table.ValueParam("$updated_at", types.TimestampValue(uint64(ts.UnixMicro()))),
			),
		)
		return err
	})
}
