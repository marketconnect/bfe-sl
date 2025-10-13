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
	UpdateUserNotifyByEmail(ctx context.Context, userID uint64, notify bool) error
	RevokePermission(ctx context.Context, permissionID uint64) error
	GetUserPermissions(ctx context.Context, userID uint64) ([]models.UserPermission, error)
	GetFilePermissions(ctx context.Context, paths []string) (map[string]string, error)
	LogFileView(ctx context.Context, userID uint64, fileKey string) error
	GetLastViewTimes(ctx context.Context, userID uint64, fileKeys []string) (map[string]time.Time, error)
	GetPermissionsForUsers(ctx context.Context, userIDs []uint64) (map[uint64][]models.UserPermission, error)
	GetViewLogsForUsersAndFiles(ctx context.Context, userIDs []uint64, fileKeys []string) (map[string]map[uint64]time.Time, error)
	CreateArchiveJob(ctx context.Context, job *models.ArchiveJob) error
	GetArchiveJob(ctx context.Context, jobID uint64) (*models.ArchiveJob, error)
	UpdateArchiveJobStatus(ctx context.Context, jobID uint64, status, archiveKey, errorMessage string) error
	UpsertFilePermissions(ctx context.Context, permissions map[string]string) error
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
		SELECT id, created_at, updated_at, username, alias, email, password_hash, is_admin, created_by, notify_by_email
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
				&user.Email,
				&user.PasswordHash,
				&user.IsAdmin,
				&user.CreatedBy,
				&user.NotifyByEmail,
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
		SELECT id, created_at, updated_at, username, alias, email, password_hash, is_admin, created_by, notify_by_email
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
				named.Optional("email", &user.Email),
				named.Required("password_hash", &user.PasswordHash),
				named.Required("is_admin", &user.IsAdmin),
				named.Optional("created_by", &user.CreatedBy),
				named.Required("notify_by_email", &user.NotifyByEmail),
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

func (s *YdbStore) GetFilePermissions(ctx context.Context, paths []string) (map[string]string, error) {
	if len(paths) == 0 {
		return make(map[string]string), nil
	}

	permissions := make(map[string]string)

	pathList := make([]types.Value, len(paths))
	for i, p := range paths {
		pathList[i] = types.UTF8Value(p)
	}

	query := `
		DECLARE $paths AS List<Utf8>;

		SELECT path, access_type
		FROM file_permissions
		WHERE path IN $paths;
	`
	err := s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$paths", types.ListValue(pathList...)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var path *string
				var accessType *string
				err = res.ScanNamed(
					named.Optional("path", &path),
					named.Optional("access_type", &accessType),
				)
				if err != nil {
					return err
				}
				if path != nil && accessType != nil {
					permissions[*path] = *accessType
				}
			}
		}

		return res.Err()
	})

	if err != nil {
		return nil, fmt.Errorf("ydb query failed in GetFilePermissions: %w", err)
	}
	return permissions, nil
}

func (s *YdbStore) LogFileView(ctx context.Context, userID uint64, fileKey string) error {
	query := `
		DECLARE $user_id AS Uint64;
		DECLARE $file_key AS Utf8;
		DECLARE $last_viewed_at AS Timestamp;

		UPSERT INTO file_view_logs (user_id, file_key, last_viewed_at)
		VALUES ($user_id, $file_key, $last_viewed_at);
	`
	ts := time.Now()
	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.Uint64Value(userID)),
				table.ValueParam("$file_key", types.UTF8Value(fileKey)),
				table.ValueParam("$last_viewed_at", types.TimestampValueFromTime(ts)),
			),
		)
		return err
	})
}

func (s *YdbStore) GetLastViewTimes(ctx context.Context, userID uint64, fileKeys []string) (map[string]time.Time, error) {
	if len(fileKeys) == 0 {
		return make(map[string]time.Time), nil
	}

	viewTimes := make(map[string]time.Time)

	keyList := make([]types.Value, len(fileKeys))
	for i, key := range fileKeys {
		keyList[i] = types.UTF8Value(key)
	}

	query := `
		DECLARE $user_id AS Uint64;
		DECLARE $file_keys AS List<Utf8>;

		SELECT file_key, last_viewed_at
		FROM file_view_logs
		WHERE user_id = $user_id AND file_key IN $file_keys;
	`
	err := s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.Uint64Value(userID)),
				table.ValueParam("$file_keys", types.ListValue(keyList...)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var fileKey *string
				var lastViewedAt *time.Time
				err = res.ScanNamed(
					named.Optional("file_key", &fileKey),
					named.Optional("last_viewed_at", &lastViewedAt),
				)
				if err != nil {
					return err
				}
				if fileKey != nil && lastViewedAt != nil {
					viewTimes[*fileKey] = *lastViewedAt
				}
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	return viewTimes, nil
}

func (s *YdbStore) GetPermissionsForUsers(ctx context.Context, userIDs []uint64) (map[uint64][]models.UserPermission, error) {
	if len(userIDs) == 0 {
		return make(map[uint64][]models.UserPermission), nil
	}

	resultMap := make(map[uint64][]models.UserPermission)
	for _, id := range userIDs {
		resultMap[id] = []models.UserPermission{}
	}

	idList := make([]types.Value, len(userIDs))
	for i, id := range userIDs {
		idList[i] = types.Uint64Value(id)
	}

	query := `
		DECLARE $user_ids AS List<Uint64>;
		SELECT id, created_at, updated_at, user_id, folder_prefix
		FROM user_permissions
		WHERE user_id IN $user_ids;
	`
	err := s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_ids", types.ListValue(idList...)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var p models.UserPermission
				err = res.Scan(
					&p.ID,
					&p.CreatedAt,
					&p.UpdatedAt,
					&p.UserID,
					&p.FolderPrefix,
				)
				if err != nil {
					return fmt.Errorf("scan failed for permission: %w", err)
				}
				resultMap[p.UserID] = append(resultMap[p.UserID], p)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, fmt.Errorf("ydb query failed in GetPermissionsForUsers: %w", err)
	}

	return resultMap, nil
}

func (s *YdbStore) GetViewLogsForUsersAndFiles(ctx context.Context, userIDs []uint64, fileKeys []string) (map[string]map[uint64]time.Time, error) {
	if len(userIDs) == 0 || len(fileKeys) == 0 {
		return make(map[string]map[uint64]time.Time), nil
	}

	resultMap := make(map[string]map[uint64]time.Time)

	userIDList := make([]types.Value, len(userIDs))
	for i, id := range userIDs {
		userIDList[i] = types.Uint64Value(id)
	}

	fileKeyList := make([]types.Value, len(fileKeys))
	for i, key := range fileKeys {
		fileKeyList[i] = types.UTF8Value(key)
	}

	query := `
		DECLARE $user_ids AS List<Uint64>;
		DECLARE $file_keys AS List<Utf8>;

		SELECT user_id, file_key, last_viewed_at
		FROM file_view_logs
		WHERE user_id IN $user_ids AND file_key IN $file_keys;
	`
	err := s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_ids", types.ListValue(userIDList...)),
				table.ValueParam("$file_keys", types.ListValue(fileKeyList...)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var userID *uint64
				var fileKey *string
				var lastViewedAt *time.Time
				err = res.ScanNamed(
					named.Optional("user_id", &userID),
					named.Optional("file_key", &fileKey),
					named.Optional("last_viewed_at", &lastViewedAt),
				)
				if err != nil {
					return err
				}

				if userID == nil || fileKey == nil || lastViewedAt == nil {
					continue
				}

				if _, ok := resultMap[*fileKey]; !ok {
					resultMap[*fileKey] = make(map[uint64]time.Time)
				}
				resultMap[*fileKey][*userID] = *lastViewedAt
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	return resultMap, nil
}

func (s *YdbStore) GetAllUsers(ctx context.Context, adminID uint64) ([]models.User, error) {
	var users []models.User

	var query string
	var params *table.QueryParameters

	if adminID == 1 { // Super admin
		query = `
			SELECT id, created_at, updated_at, username, alias, email, is_admin, created_by, notify_by_email
			FROM users;
		`
		params = table.NewQueryParameters()
	} else { // Regular admin
		query = `
			DECLARE $created_by AS Uint64;
			SELECT id, created_at, updated_at, username, alias, email, is_admin, created_by, notify_by_email
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
					named.Optional("email", &u.Email),
					named.Required("is_admin", &u.IsAdmin),
					named.Optional("created_by", &u.CreatedBy),
					named.Required("notify_by_email", &u.NotifyByEmail),
				)
				if err != nil {
					return err
				}

				users = append(users, u)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return []models.User{}, nil
	}

	userIDs := make([]uint64, len(users))
	userMap := make(map[uint64]*models.User, len(users))
	for i := range users {
		userIDs[i] = users[i].ID
		userMap[users[i].ID] = &users[i]
	}

	allPermissions, err := s.GetPermissionsForUsers(ctx, userIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions for users: %w", err)
	}

	for userID, perms := range allPermissions {
		if user, ok := userMap[userID]; ok {
			user.Permissions = perms
		}
	}

	return users, nil
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
		DECLARE $email AS Optional<Utf8>;
		DECLARE $password_hash AS Utf8;
		DECLARE $is_admin AS Bool;
		DECLARE $created_by AS Optional<Uint64>;
		DECLARE $notify_by_email AS Bool;

		UPSERT INTO users (id, created_at, updated_at, username, alias, email, password_hash, is_admin, created_by, notify_by_email)
		VALUES ($id, $created_at, $updated_at, $username, $alias, $email, $password_hash, $is_admin, $created_by, $notify_by_email);
	`

	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(user.ID)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(ts)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(ts)),
				table.ValueParam("$username", types.UTF8Value(user.Username)),
				table.ValueParam("$alias", types.NullableUTF8Value(user.Alias)),
				table.ValueParam("$email", types.NullableUTF8Value(user.Email)),
				table.ValueParam("$password_hash", types.UTF8Value(user.PasswordHash)),
				table.ValueParam("$is_admin", types.BoolValue(user.IsAdmin)),
				table.ValueParam("$created_by", types.NullableUint64Value(user.CreatedBy)),
				table.ValueParam("$notify_by_email", types.BoolValue(user.NotifyByEmail)),
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
		DECLARE $email AS Optional<Utf8>;
		DECLARE $password_hash AS Utf8;
		DECLARE $is_admin AS Bool;
		DECLARE $created_by AS Optional<Uint64>;
		DECLARE $notify_by_email AS Bool;

		UPSERT INTO users (id, created_at, updated_at, username, alias, email, password_hash, is_admin, created_by, notify_by_email)
		VALUES ($id, $created_at, $updated_at, $username, $alias, $email, $password_hash, $is_admin, $created_by, $notify_by_email);
	`
	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(user.ID)),
				table.ValueParam("$created_at", types.NullableTimestampValueFromTime(user.CreatedAt)),
				table.ValueParam("$updated_at", types.NullableTimestampValueFromTime(user.UpdatedAt)),
				table.ValueParam("$username", types.UTF8Value(user.Username)),
				table.ValueParam("$alias", types.NullableUTF8Value(user.Alias)),
				table.ValueParam("$email", types.NullableUTF8Value(user.Email)),
				table.ValueParam("$password_hash", types.UTF8Value(user.PasswordHash)),
				table.ValueParam("$is_admin", types.BoolValue(user.IsAdmin)),
				table.ValueParam("$created_by", types.NullableUint64Value(user.CreatedBy)),
				table.ValueParam("$notify_by_email", types.BoolValue(user.NotifyByEmail)),
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

func (s *YdbStore) UpdateUserNotifyByEmail(ctx context.Context, userID uint64, notify bool) error {
	query := `
		DECLARE $id AS Uint64;
		DECLARE $notify_by_email AS Bool;
		DECLARE $updated_at AS Timestamp;

		UPDATE users
		SET notify_by_email = $notify_by_email, updated_at = $updated_at
		WHERE id = $id;
	`
	ts := time.Now()
	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.Uint64Value(userID)),
				table.ValueParam("$notify_by_email", types.BoolValue(notify)),
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

func (s *YdbStore) UpsertFilePermissions(ctx context.Context, permissions map[string]string) error {
	if len(permissions) == 0 {
		return nil
	}

	query := `
		DECLARE $permissionsData AS List<Struct<
			path: Utf8,
			access_type: Utf8
		>>;

		UPSERT INTO file_permissions
		SELECT
			path,
			access_type
		FROM AS_TABLE($permissionsData);
	`

	structs := make([]types.Value, 0, len(permissions))

	for path, accessType := range permissions {
		st := types.StructValue(
			types.StructFieldValue("path", types.UTF8Value(path)),
			types.StructFieldValue("access_type", types.UTF8Value(accessType)),
		)
		structs = append(structs, st)
	}

	return s.Driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$permissionsData", types.ListValue(structs...)),
			),
		)
		return err
	})
}
