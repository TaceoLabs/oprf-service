-- %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-- %               Address  Singleton                 %
-- %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
CREATE TABLE evm_address (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE,
    address TEXT NOT NULL,

    CONSTRAINT evm_address_singleton CHECK (id = TRUE)
);


-- %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-- %                DLog Shares                       %
-- %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
CREATE TABLE shares (
    id BYTEA PRIMARY KEY NOT NULL,
    share BYTEA,
    epoch BIGINT NOT NULL, -- we use BigInt to securly convert from u32 to i64
    public_key BYTEA NOT NULL,
    deleted BOOLEAN NOT NULL DEFAULT false,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT deleted_share_null
    CHECK (
        (deleted = false AND share IS NOT NULL)
     OR (deleted = true  AND share IS NULL)
    )
);

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER shares_set_updated_at
BEFORE UPDATE ON shares
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
