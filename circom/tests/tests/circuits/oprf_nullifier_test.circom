pragma circom 2.2.2;

include "client_side_proofs/oprf_nullifier.circom";

component main {public [cred_pk, current_timestamp, merkle_root, depth, rp_id, action, oprf_pk, signal_hash, nonce]} = OprfNullifier(30);
