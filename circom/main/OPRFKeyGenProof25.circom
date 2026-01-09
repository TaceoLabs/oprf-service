pragma circom 2.2.0;
include "oprf_keys/keygen.circom";

component main {public [degree, pks, nonces]} = KeyGen(2, 5);
