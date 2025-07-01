-- Create tokens table for storing verification and password reset tokens
CREATE TABLE IF NOT EXISTS tokens (
    token_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_type VARCHAR(50) NOT NULL, -- 'verification' or 'password_reset'
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create an index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS tokens_user_id_idx ON tokens(user_id);

-- Create an index on token_type for faster lookups
CREATE INDEX IF NOT EXISTS tokens_token_type_idx ON tokens(token_type);
