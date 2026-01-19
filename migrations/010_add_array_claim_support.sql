-- Add support for array claim values (explicit single vs array in JWT)
-- This allows claims to be either a single string or an array of strings

-- Add claim_value_kind column (single or array)
ALTER TABLE claim_maps
ADD COLUMN claim_value_kind TEXT NOT NULL DEFAULT 'single';

-- Add claim_value_json column for array values (JSON text containing array of strings)
ALTER TABLE claim_maps
ADD COLUMN claim_value_json TEXT;

-- Add check constraint for valid claim_value_kind values
ALTER TABLE claim_maps
ADD CONSTRAINT claim_value_kind_check CHECK (claim_value_kind IN ('single', 'array'));

-- Add comment for documentation
COMMENT ON COLUMN claim_maps.claim_value_kind IS 'Type of claim value: ''single'' for string or ''array'' for array of strings';
COMMENT ON COLUMN claim_maps.claim_value_json IS 'JSON array of strings when claim_value_kind=''array'', e.g. ["value1", "value2"]';

-- Migrate existing data: all existing claims are 'single' (already set by DEFAULT)
-- claim_value_json stays NULL for existing rows (single values use claim_value column)
