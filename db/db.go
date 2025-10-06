package db

import (
	"context"
	"log"

	"github.com/marketconnect/bfe-sl/config"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	yc "github.com/ydb-platform/ydb-go-yc"
)

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
