package db

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
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
	GetAllUsers(ctx context.Context, adminID uint64) ([]models.User, error)
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
	val, err := rand.Int(rand.Reader, new(big.Int).SetUint64(^uint64(0)))
	if err != nil {
		return 0, err
	}
	return val.Uint64(), nil
}

func (s *YdbStore) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	log.Printf("DEBUG: GetUserByUsername called for user: '%s'", username)

	var user models.User
	_ = user.VersionCheck
	var found bool

	query := `
		DECLARE $username AS Utf8;
		SELECT id, created_at, updated_at, username, alias, password_hash, is_admin, created_by
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
			log.Println("DEBUG: User found in DB. Attempting to scan values using res.Scan()...")
			found = true
			// Используем res.Scan() вместо res.ScanNamed()
			// Порядок важен и должен соответствовать SELECT
			err := res.Scan(
				&user.ID,
				&user.CreatedAt,
				&user.UpdatedAt,
				&user.Username,
				&user.Alias, // &user.Alias здесь имеет тип **string, что является правильным для сканирования nullable-значения в указатель
				&user.PasswordHash,
				&user.IsAdmin,
				&user.CreatedBy,
			)
			if err != nil {
				log.Printf("DEBUG: res.Scan FAILED with error: %v", err)
				return fmt.Errorf("scan failed: %w", err)
			}
			log.Println("DEBUG: res.Scan successful.")
		} else {
			log.Println("DEBUG: User not found in result set.")
		}
		return res.Err()
	})

	if err != nil {
		log.Printf("DEBUG: The entire YDB 'Do' block failed with error: %v", err)
		return nil, fmt.Errorf("ydb query failed in GetUserByUsername: %w", err)
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
		SELECT id, created_at, updated_at, username, alias, password_hash, is_admin, created_by
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
			err := res.ScanNamed(
				named.Required("id", &user.ID),
				named.Optional("created_at", &user.CreatedAt),
				named.Optional("updated_at", &user.UpdatedAt),
				named.Required("username", &user.Username),
				named.Optional("alias", &user.Alias),
				named.Required("password_hash", &user.PasswordHash),
				named.Required("is_admin", &user.IsAdmin),
				named.Optional("created_by", &user.CreatedBy),
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, fmt.Errorf("ydb query failed in GetUserByID: %w", err)
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

	log.Printf("DEBUG: GetUserPermissions called for userID: %d", userID)

	var permissions []models.UserPermission

	query := `
		DECLARE $user_id AS Uint64;
		SELECT id, created_at, updated_at, user_id, folder_prefix
		FROM user_permissions
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
				log.Println("DEBUG: Found a permission row, scanning...")
				var p models.UserPermission
				err = res.Scan(
					&p.ID,
					&p.CreatedAt,
					&p.UpdatedAt,
					&p.UserID,
					&p.FolderPrefix,
				)
				if err != nil {
					log.Printf("DEBUG: Scan failed for permission row: %v", err)
					return fmt.Errorf("scan failed for permission: %w", err)
				}

				permissions = append(permissions, p)
			}
		}
		log.Printf("DEBUG: Finished scanning. Total permissions found: %d", len(permissions))
		return res.Err()
	})

	if err != nil {
		log.Printf("DEBUG: GetUserPermissions 'Do' block failed with error: %v", err)
		return nil, fmt.Errorf("ydb query failed in GetUserPermissions: %w", err)
	}

	return permissions, nil
}

func (s *YdbStore) GetAllUsers(ctx context.Context, adminID uint64) ([]models.User, error) {
	var users []models.User

	var query string
	var params *table.QueryParameters

	if adminID == 1 { // Super admin
		query = `
			SELECT id, created_at, updated_at, username, alias, is_admin, created_by
			FROM users;
		`
		params = table.NewQueryParameters()
	} else { // Regular admin
		query = `
			DECLARE $created_by AS Uint64;
			SELECT id, created_at, updated_at, username, alias, is_admin, created_by
			FROM users
			WHERE created_by = $created_by;
		`
		params = table.NewQueryParameters(
			table.ValueParam("$created_by", types.Uint64Value(adminID)),
		)
	}

	err := s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query, params)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var u models.User
				err = res.ScanNamed(
					named.Required("id", &u.ID),
					named.Optional("created_at", &u.CreatedAt),
					named.Optional("updated_at", &u.UpdatedAt),
					named.Required("username", &u.Username),
					named.Optional("alias", &u.Alias),
					named.Required("is_admin", &u.IsAdmin),
					named.Optional("created_by", &u.CreatedBy),
				)
				if err != nil {
					return err
				}

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
			err := res.Scan(
				&job.ID,
				&job.UserID,
				&job.Status,
				&job.ArchiveKey,
				&job.ErrorMessage,
				&job.CreatedAt,
				&job.UpdatedAt,
			)
			if err != nil {
				return err
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, fmt.Errorf("ydb query failed: %w", err)
	}
	if !found {
		return nil, ErrNotFound
	}
	return &job, nil
}

func (s *YdbStore) CreateUser(ctx context.Context, user *models.User) error {
	if user.ID == 0 {
		id, err := newID()
		if err != nil {
			return err
		}
		user.ID = id
	}
	ts := time.Now()

	query := `
		DECLARE $id AS Uint64;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;
		DECLARE $username AS Utf8;
		DECLARE $alias AS Optional<Utf8>;
		DECLARE $password_hash AS Utf8;
		DECLARE $is_admin AS Bool;
		DECLARE $created_by AS Optional<Uint64>;

		UPSERT INTO users (id, created_at, updated_at, username, alias, password_hash, is_admin, created_by)
		VALUES ($id, $created_at, $updated_at, $username, $alias, $password_hash, $is_admin, $created_by);
	`

	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(user.ID)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(ts)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(ts)),
				table.ValueParam("$username", types.UTF8Value(user.Username)),
				table.ValueParam("$alias", types.NullableUTF8Value(user.Alias)),
				table.ValueParam("$password_hash", types.UTF8Value(user.PasswordHash)),
				table.ValueParam("$is_admin", types.BoolValue(user.IsAdmin)),
				table.ValueParam("$created_by", types.NullableUint64Value(user.CreatedBy)),
			),
		)
		return err
	})
}

func (s *YdbStore) UpdateUser(ctx context.Context, user *models.User) error {
	now := time.Now()
	user.UpdatedAt = &now

	query := `
		DECLARE $id AS Uint64;
		DECLARE $created_at AS Optional<Timestamp>;
		DECLARE $updated_at AS Optional<Timestamp>;
		DECLARE $username AS Utf8;
		DECLARE $alias AS Optional<Utf8>;
		DECLARE $password_hash AS Utf8;
		DECLARE $is_admin AS Bool;
		DECLARE $created_by AS Optional<Uint64>;

		UPSERT INTO users (id, created_at, updated_at, username, alias, password_hash, is_admin, created_by)
		VALUES ($id, $created_at, $updated_at, $username, $alias, $password_hash, $is_admin, $created_by);
	`
	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(user.ID)),
				table.ValueParam("$created_at", types.NullableTimestampValueFromTime(user.CreatedAt)),
				table.ValueParam("$updated_at", types.NullableTimestampValueFromTime(user.UpdatedAt)),
				table.ValueParam("$username", types.UTF8Value(user.Username)),
				table.ValueParam("$alias", types.NullableUTF8Value(user.Alias)),
				table.ValueParam("$password_hash", types.UTF8Value(user.PasswordHash)),
				table.ValueParam("$is_admin", types.BoolValue(user.IsAdmin)),
				table.ValueParam("$created_by", types.NullableUint64Value(user.CreatedBy)),
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
				table.ValueParam("$updated_at", types.TimestampValueFromTime(ts)),
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
		// Используем TxControl с явным Begin и Commit для гарантии сохранения изменений.
		txControl := table.TxControl(
			table.BeginTx(table.WithSerializableReadWrite()),
			table.CommitTx(),
		)
		_, _, err := session.Execute(ctx, txControl, query,
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
				table.ValueParam("$created_at", types.TimestampValueFromTime(ts)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(ts)),
				table.ValueParam("$user_id", types.Uint64Value(permission.UserID)),
				table.ValueParam("$folder_prefix", types.UTF8Value(*permission.FolderPrefix)),
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
				table.ValueParam("$created_at", types.TimestampValueFromTime(ts)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(ts)),
			),
		)
		return err
	})
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
				table.ValueParam("$archive_key", types.NullableUTF8Value(&archiveKey)),
				table.ValueParam("$error_message", types.NullableUTF8Value(&errorMessage)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(ts)),
			),
		)
		return err
	})
}
