-- Add up migration script here

CREATE TABLE in_progress_keygens (
    id BYTEA NOT NULL,
    pending_epoch BIGINT NOT NULL,
    pending_share BYTEA,
    intermediates BYTEA NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (id, pending_epoch)
);

CREATE TRIGGER in_progress_keygens_set_updated_at
BEFORE UPDATE ON in_progress_keygens
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
