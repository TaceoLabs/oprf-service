-- Add down migration script here
DROP TABLE IF EXISTS node_information;

CREATE TABLE evm_address (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE,
    address TEXT NOT NULL,

    CONSTRAINT evm_address_singleton CHECK (id = TRUE)
);
