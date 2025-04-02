-- Create simplified users table with only essential fields, 
-- but maintain compatibility with repository code

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,  -- Repository code expects string UUID
    email VARCHAR(255) NOT NULL UNIQUE, -- Using username as email in the code
    username VARCHAR(100), -- Not strictly required by repository code
    hashed_password VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NULL, -- Make optional but keep for repository code
    last_name VARCHAR(100) NULL, -- Make optional but keep for repository code
    is_email_verified BOOLEAN DEFAULT FALSE, -- Required by repository code
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create an index on email for faster lookups
CREATE INDEX IF NOT EXISTS users_email_idx ON users(email);
