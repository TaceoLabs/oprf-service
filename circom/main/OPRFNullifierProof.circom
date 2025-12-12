pragma circom 2.2.0;
include "client_side_proofs/oprf_nullifier.circom";

component main {public [cred_type_id, cred_pk, current_time_stamp, cred_genesis_issued_at_limit, merkle_root, depth, rp_id, action, oprf_pk, signal_hash, nonce]} = OprfNullifier(30);
