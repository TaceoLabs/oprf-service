-- Data keys can also be wrapped under a local master key, so the key id is no longer an AWS ARN.
ALTER TABLE data_keys RENAME COLUMN kms_key_arn TO wrapping_key_id;

ALTER TABLE data_keys
    DROP CONSTRAINT data_keys_wrapping_check,
    ADD CONSTRAINT data_keys_wrapping_check
    CHECK (wrapping IN ('awsKms', 'localKeyV1'));
