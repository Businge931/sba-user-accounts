-- Create users table with columns matching the repository code

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,  -- Repository code seems to expect string UUID
    email VARCHAR(255) NOT NULL UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create an index on email for faster lookups
CREATE INDEX IF NOT EXISTS users_email_idx ON users(email);
