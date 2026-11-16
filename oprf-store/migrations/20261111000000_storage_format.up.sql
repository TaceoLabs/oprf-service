-- %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-- %                  Data keys                       %
-- %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
CREATE TABLE data_keys (
    id UUID PRIMARY KEY,
    wrapped_key BYTEA NOT NULL,
    wrapping TEXT NOT NULL,
    kms_key_arn TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT data_keys_wrapping_check
    CHECK (wrapping IN ('awsKms'))
);

-- %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-- %          Storage format of secret columns        %
-- %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-- Existing rows become 'direct' (plaintext) via the column default.
ALTER TABLE shares
    ADD COLUMN storage_format TEXT NOT NULL DEFAULT 'direct',
    ADD COLUMN data_key_id UUID NULL REFERENCES data_keys(id),
    ADD CONSTRAINT shares_storage_format_check
    CHECK (storage_format IN ('direct', 'envelopeV1')),
    ADD CONSTRAINT shares_data_key_matches_format
    CHECK ((storage_format = 'envelopeV1') = (data_key_id IS NOT NULL));

ALTER TABLE in_progress_keygens
    ADD COLUMN storage_format TEXT NOT NULL DEFAULT 'direct',
    ADD COLUMN data_key_id UUID NULL REFERENCES data_keys(id),
    ADD CONSTRAINT in_progress_keygens_storage_format_check
    CHECK (storage_format IN ('direct', 'envelopeV1')),
    ADD CONSTRAINT in_progress_keygens_data_key_matches_format
    CHECK ((storage_format = 'envelopeV1') = (data_key_id IS NOT NULL));
