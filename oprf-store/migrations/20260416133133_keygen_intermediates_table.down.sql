-- Add down migration script here
DROP TRIGGER in_progress_keygens_set_updated_at ON in_progress_keygens;
DROP TABLE in_progress_keygens;
