-- Preserve historical edges. New edges require a virtual parent; legacy edges
-- remain readable/removable and are reported by scripts/group-contract-audit.sql.
CREATE FUNCTION enforce_virtual_group_parent() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_tenant uuid; child_tenant uuid; parent_virtual boolean;
BEGIN
    LOCK TABLE group_groups IN SHARE ROW EXCLUSIVE MODE;
    SELECT tenant_id, is_virtual INTO parent_tenant, parent_virtual
      FROM groups WHERE id=NEW.parent_group_id AND deleted_at IS NULL;
    SELECT tenant_id INTO child_tenant FROM groups
      WHERE id=NEW.child_group_id AND deleted_at IS NULL;
    IF parent_tenant IS NULL OR child_tenant IS NULL OR parent_tenant <> child_tenant THEN
        RAISE EXCEPTION 'Group members must be active and belong to the same tenant' USING ERRCODE='23514';
    END IF;
    IF NOT parent_virtual THEN
        RAISE EXCEPTION 'Only virtual bundles can contain groups' USING ERRCODE='23514';
    END IF;
    IF EXISTS (
        WITH RECURSIVE reachable(id) AS (
            SELECT NEW.child_group_id
            UNION
            SELECT gg.child_group_id FROM group_groups gg JOIN reachable r ON gg.parent_group_id=r.id
        ) SELECT 1 FROM reachable WHERE id=NEW.parent_group_id
    ) THEN
        RAISE EXCEPTION 'A group cannot contain itself or create a membership cycle' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER virtual_group_parent BEFORE INSERT OR UPDATE ON group_groups
    FOR EACH ROW EXECUTE FUNCTION enforce_virtual_group_parent();

CREATE FUNCTION enforce_group_type_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Match membership writes: prevent a concurrent edit from making a physical parent.
    LOCK TABLE group_groups IN SHARE ROW EXCLUSIVE MODE;
    IF OLD.is_virtual AND NOT NEW.is_virtual AND
       EXISTS (SELECT 1 FROM group_groups WHERE parent_group_id=NEW.id) THEN
        RAISE EXCEPTION 'Remove all member groups before changing a virtual bundle to a regular group' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER group_type_change BEFORE UPDATE OF is_virtual ON groups
    FOR EACH ROW EXECUTE FUNCTION enforce_group_type_change();

-- Deprecated compatibility field; old requests cannot re-enable publication.
ALTER TABLE oauth_clients ALTER COLUMN ignore_virtual_groups SET DEFAULT true;
-- Keep existing values for the compatibility audit; token issuance ignores them.
