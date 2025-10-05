package db

import (
	"context"
	"fmt"
	"log"

	"github.com/marketconnect/bfe-sl/config"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/table"
	yc "github.com/ydb-platform/ydb-go-yc"
)

// InitYDB инициализирует соединение с YDB для работы в Yandex Cloud
func InitYDB(ctx context.Context, cfg *config.Config) (*ydb.Driver, error) {
	driver, err := ydb.Open(ctx, cfg.YDBEndpoint,
		ydb.WithDatabase(cfg.YDBDatabasePath),
		yc.WithMetadataCredentials(),
	)
	if err != nil {
		return nil, err
	}

	log.Println("Successfully connected to YDB")
	return driver, nil
}

// CreateTables выполняет идемпотентную инициализацию схемы БД для продакшена.
// Сначала проверяется наличие каждой таблицы, и только при ее отсутствии выполняется создание.
func CreateTables(ctx context.Context, driver *ydb.Driver) error {
	log.Println("Initializing database schema for production...")

	// Определяем схемы для всех необходимых таблиц
	schemas := map[string]string{
		"users": `
			CREATE TABLE users (
				id Uint64,
				created_at Timestamp,
				updated_at Timestamp,
				username Utf8,
				alias Utf8,
				password_hash Utf8,
				is_admin Bool,
				PRIMARY KEY (id),
				INDEX username_index GLOBAL ON (username)
			);`,
		"user_permissions": `
			CREATE TABLE user_permissions (
				id Uint64,
				created_at Timestamp,
				updated_at Timestamp,
				user_id Uint64,
				folder_prefix Utf8,
				PRIMARY KEY (id),
				INDEX user_id_index GLOBAL ON (user_id)
			);`,
		"archive_jobs": `
			CREATE TABLE archive_jobs (
				id Uint64,
				user_id Uint64,
				status Utf8,
				archive_key Utf8,
				error_message Utf8,
				created_at Timestamp,
				updated_at Timestamp,
				PRIMARY KEY (id)
			);`,
	}

	for tableName, schema := range schemas {
		err := driver.Table().Do(ctx, func(ctx context.Context, s table.Session) error {
			// 1. Проверяем, существует ли таблица
			_, err := s.DescribeTable(ctx, tableName)
			if err == nil {
				// Ошибки нет - таблица уже существует. Это нормальный сценарий.
				log.Printf("Table '%s' already exists, skipping creation.", tableName)
				return nil
			}

			// 2. Если есть ошибка, проверяем, что это именно ошибка "объект не найден"
			if ydb.IsOperationErrorSchemeError(err) {
				// Это ожидаемая ошибка, если таблицы нет. Создаем ее.
				log.Printf("Table '%s' not found, creating...", tableName)
				return s.ExecuteSchemeQuery(ctx, schema)
			}

			// 3. Если это любая другая ошибка (сеть, права) - это критическая проблема.
			return fmt.Errorf("unexpected error describing table %s: %w", tableName, err)

		}, table.WithIdempotent())

		if err != nil {
			// Если на любом из шагов произошла критическая ошибка, прерываем инициализацию.
			return fmt.Errorf("failed to initialize schema for table %s: %w", tableName, err)
		}
	}

	log.Println("Database schema is up to date.")
	return nil
}
