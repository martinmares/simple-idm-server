-- Add updated_at columns to tables that are missing them

-- Groups table
ALTER TABLE groups
ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- OAuth clients table
ALTER TABLE oauth_clients
ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Claim maps table
ALTER TABLE claim_maps
ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- User groups junction table (for completeness)
ALTER TABLE user_groups
ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Create triggers to automatically update updated_at on row updates

-- Trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to groups
CREATE TRIGGER update_groups_updated_at
    BEFORE UPDATE ON groups
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Apply trigger to oauth_clients
CREATE TRIGGER update_oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Apply trigger to claim_maps
CREATE TRIGGER update_claim_maps_updated_at
    BEFORE UPDATE ON claim_maps
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Apply trigger to users (already has updated_at but no trigger)
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
