-- +migrate Up
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password TEXT,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    google_id TEXT,
    role VARCHAR(36) NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ
);

-- Unique email and google_id where deleted_at IS NULL (enforce unique among active users)
CREATE UNIQUE INDEX unique_email_active ON users(email) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX unique_google_id_active ON users(google_id) WHERE google_id IS NOT NULL AND deleted_at IS NULL;

-- +migrate Down
DROP TABLE users;