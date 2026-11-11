DROP TABLE IF EXISTS evm_address;

CREATE TABLE node_information (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE,
    eth_address TEXT NOT NULL,
    party_id INTEGER NOT NULL,
    threshold INTEGER NOT NULL,

    CONSTRAINT node_information_singleton CHECK (id = TRUE)
);
