-- Create table for tracking failed device verification attempts (brute force protection)
CREATE TABLE IF NOT EXISTS device_verification_attempts (
    id SERIAL PRIMARY KEY,
    user_code TEXT NOT NULL,
    ip_address TEXT,
    failed_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index pro rychlé vyhledávání attempts per user_code
CREATE INDEX IF NOT EXISTS idx_device_verification_attempts_user_code ON device_verification_attempts(user_code);
CREATE INDEX IF NOT EXISTS idx_device_verification_attempts_failed_at ON device_verification_attempts(failed_at);
