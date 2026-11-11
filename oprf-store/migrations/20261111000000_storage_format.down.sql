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
