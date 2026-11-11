-- Add up migration script here
CREATE TABLE chain_cursor (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id = TRUE),
    block BIGINT NOT NULL,
    idx BIGINT NOT NULL
);

INSERT INTO chain_cursor (block, idx)
VALUES (0, 0);