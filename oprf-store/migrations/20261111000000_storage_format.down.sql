-- Refuse to run while encrypted data or wrapped data keys exist: dropping the columns and the
-- data_keys table would destroy the only copy of the wrapped data keys and make every
-- envelope-encrypted value unreadable. Re-encrypt to 'direct' and delete the data keys first.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM shares WHERE storage_format <> 'direct')
        OR EXISTS (SELECT 1 FROM in_progress_keygens WHERE storage_format <> 'direct')
        OR EXISTS (SELECT 1 FROM data_keys)
    THEN
        RAISE EXCEPTION 'refusing to undo the storage_format migration: rows that are not stored as ''direct'' or wrapped data keys exist; dropping them would destroy key material';
    END IF;
END
$$;

ALTER TABLE in_progress_keygens
    DROP CONSTRAINT in_progress_keygens_data_key_matches_format,
    DROP CONSTRAINT in_progress_keygens_storage_format_check,
    DROP COLUMN data_key_id,
    DROP COLUMN storage_format;

ALTER TABLE shares
    DROP CONSTRAINT shares_data_key_matches_format,
    DROP CONSTRAINT shares_storage_format_check,
    DROP COLUMN data_key_id,
    DROP COLUMN storage_format;

DROP TABLE data_keys;
