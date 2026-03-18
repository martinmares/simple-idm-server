-- Optional trigram indexes for faster LIKE/ILIKE search.
-- This migration is best-effort: if pg_trgm cannot be enabled due to permissions,
-- migration continues without failure.

DO $$
BEGIN
    BEGIN
        CREATE EXTENSION IF NOT EXISTS pg_trgm;
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'pg_trgm extension not created (insufficient privileges), skipping trigram indexes';
        WHEN undefined_file THEN
            RAISE NOTICE 'pg_trgm extension not available, skipping trigram indexes';
    END;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
        -- Users: combined text search (username/email/name/note)
        EXECUTE '
            CREATE INDEX IF NOT EXISTS idx_users_search_trgm
            ON users USING GIN (
                LOWER(
                    COALESCE(username, '''') || '' '' ||
                    COALESCE(email, '''') || '' '' ||
                    COALESCE(first_name, '''') || '' '' ||
                    COALESCE(last_name, '''') || '' '' ||
                    COALESCE(note, '''')
                ) gin_trgm_ops
            )
            WHERE deleted_at IS NULL
        ';

        -- External identities (AD): external_user_id/login_name/upn
        EXECUTE '
            CREATE INDEX IF NOT EXISTS idx_user_external_identities_search_trgm
            ON user_external_identities USING GIN (
                LOWER(
                    COALESCE(external_user_id, '''') || '' '' ||
                    COALESCE(login_name, '''') || '' '' ||
                    COALESCE(upn, '''')
                ) gin_trgm_ops
            )
            WHERE deleted_at IS NULL
              AND source = ''ad''
        ';

        -- Groups: name + description search
        EXECUTE '
            CREATE INDEX IF NOT EXISTS idx_groups_search_trgm
            ON groups USING GIN (
                LOWER(
                    COALESCE(name, '''') || '' '' ||
                    COALESCE(description, '''')
                ) gin_trgm_ops
            )
            WHERE deleted_at IS NULL
        ';
    ELSE
        RAISE NOTICE 'pg_trgm extension not available, trigram indexes were skipped';
    END IF;
END $$;
