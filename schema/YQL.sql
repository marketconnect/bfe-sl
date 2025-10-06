CREATE TABLE users (
    id Uint64 NOT NULL,
    created_at Timestamp,
    updated_at Timestamp,
    username Utf8 NOT NULL,
    alias Utf8,
    password_hash Utf8 NOT NULL,
    is_admin Bool NOT NULL,
    PRIMARY KEY (id),
    INDEX username_index GLOBAL ON (username)
);

CREATE TABLE user_permissions (
    id Uint64 NOT NULL,
    created_at Timestamp,
    updated_at Timestamp,
    user_id Uint64 NOT NULL,
    folder_prefix Utf8,
    PRIMARY KEY (id),
    INDEX user_id_index GLOBAL ON (user_id)
);

CREATE TABLE archive_jobs (
    id Uint64 NOT NULL,
    user_id Uint64 NOT NULL,
    status Utf8 NOT NULL,
    archive_key Utf8,
    error_message Utf8,
    created_at Timestamp NOT NULL,
    updated_at Timestamp NOT NULL,
    PRIMARY KEY (id)
);