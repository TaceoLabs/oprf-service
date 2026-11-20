-- Fails on the check constraint while 'localKeyV1' data keys exist.
ALTER TABLE data_keys
    DROP CONSTRAINT data_keys_wrapping_check,
    ADD CONSTRAINT data_keys_wrapping_check
    CHECK (wrapping IN ('awsKms'));

ALTER TABLE data_keys RENAME COLUMN wrapping_key_id TO kms_key_arn;
