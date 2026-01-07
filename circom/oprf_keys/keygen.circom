pragma circom 2.0.0;

include "babyjubjub/babyjubjub.circom";
include "poseidon2/poseidon2.circom";
include "circomlib/mux1.circom";

// calculates (a + b) % p, where a, b < p and p = BabyJubJub ScalarField
template AddModP() {
    signal input a;
    signal input b;
    signal output out;

    var fr = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    signal sum <== a + b; // No overflow
    out <-- sum % fr;
    signal x <-- sum \ fr;
    sum === x * fr + out;

    // We constrain out to be < p
    signal bits[251] <== Num2Bits(251)(out);
    // CompConstant enforces <=, so compare against (fr - 1).
    component cmp_const = CompConstant(fr-1);
    for(var i=0; i<251; i++) {
        cmp_const.in[i] <== bits[i];
    }
    cmp_const.in[251] <== 0;
    cmp_const.in[252] <== 0;
    cmp_const.in[253] <== 0;
    cmp_const.out === 0;

    // x must either be 0 or 1
    x * (x - 1) === 0;
}

// calculates (a + b + c) % p, where a, b, c < p and p = BabyJubJub ScalarField
template Add3ModP() {
    signal input a;
    signal input b;
    signal input c;
    signal output out;

    var fr = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    signal sum <== a + b + c; // No overflow
    out <-- sum % fr;
    signal x <-- sum \ fr;
    sum === x * fr + out;

    // We constrain out to be < p
    signal bits[251] <== Num2Bits(251)(out);
    // CompConstant enforces <=, so compare against (fr - 1).
    component cmp_const = CompConstant(fr-1);
    for(var i=0; i<251; i++) {
        cmp_const.in[i] <== bits[i];
    }
    cmp_const.in[251] <== 0;
    cmp_const.in[252] <== 0;
    cmp_const.in[253] <== 0;
    cmp_const.out === 0;

    // x must either be 0 or 1 or 2
    signal zero_or_one <== x * (x - 1);
    zero_or_one * (x - 2) === 0;
}


function log_ceil(n) {
   var n_temp = n;
   for (var i = 0; i < 254; i++) {
       if (n_temp == 0) {
          return i;
       }
       n_temp = n_temp \ 2;
   }
   return 254;
}

// Implement a * B mod P (= BabyJubJub ScalarField) via a double-add-ladder.
template MulModP(B) {
    assert(B > 0);
    var B_NUM_BITS = log_ceil(B);
    assert(B < 2**B_NUM_BITS);

    signal input a;
    signal output out;

    var b_bits[B_NUM_BITS];
    for (var i = 0; i<B_NUM_BITS; i++) {
        b_bits[i] = (B >> i) & 1;
    }

    var init = 0;
    if (b_bits[B_NUM_BITS - 1] == 1) {
        init = a;
    }

    signal result[B_NUM_BITS];
    result[0] <== init;
    component dbl[B_NUM_BITS-1];
    component dbladd[B_NUM_BITS-1];
    for(var i = 0; i < B_NUM_BITS - 1; i++) {
        var tmp = 0;
        if (b_bits[B_NUM_BITS - 2 - i] == 1){
            // double and add
            dbladd[i] = Add3ModP();
            dbladd[i].a <== result[i];
            dbladd[i].b <== result[i];
            dbladd[i].c <== a;
            tmp = dbladd[i].out;
        } else {
            // only double
            dbl[i] = AddModP();
            dbl[i].a <== result[i];
            dbl[i].b <== result[i];
            tmp = dbl[i].out;
        }
        result[i + 1] <== tmp;
    }
    out <== result[B_NUM_BITS - 1];
}

// Implement a * B mod P (= BabyJubJub ScalarField) via a double-add-ladder.
template MulModPVar(B_NUM_BITS) {
    assert(B_NUM_BITS > 0);

    signal input a;
    signal input b;
    signal output out;

    var b_bits[B_NUM_BITS] = Num2Bits(B_NUM_BITS)(b);

    signal result[B_NUM_BITS];
    result[0] <== Mux1()([0, a], b_bits[B_NUM_BITS - 1]);

    component dbl[B_NUM_BITS-1];
    component dbladd[B_NUM_BITS-1];
    for(var i = 0; i < B_NUM_BITS - 1; i++) {
        // double and add
        dbladd[i] = Add3ModP();
        dbladd[i].a <== result[i];
        dbladd[i].b <== result[i];
        dbladd[i].c <== a;

        // only double
        dbl[i] = AddModP();
        dbl[i].a <== result[i];
        dbl[i].b <== result[i];

        result[i + 1] <== Mux1()([dbl[i].out, dbladd[i].out], b_bits[B_NUM_BITS - 2 - i]);
    }
    out <== result[B_NUM_BITS - 1];
}

// Evaluates a polynomial mod P (= BabyJubJub ScalarField) at an index
template EvalPolyModPVar(DEGREE, INDEX_NUM_BITS) {
    input BabyJubJubScalarField() poly[DEGREE + 1];
    signal input index;
    signal output out;

    // Use Horners rule
    component adder_modp[DEGREE];
    component mult_modp[DEGREE];

    mult_modp[0] = MulModPVar(INDEX_NUM_BITS);
    mult_modp[0].a <== poly[DEGREE].f;
    mult_modp[0].b <== index;
    adder_modp[0] = AddModP();
    adder_modp[0].a <== mult_modp[0].out;
    adder_modp[0].b <== poly[DEGREE-1].f;

    for(var i = 1; i < DEGREE; i++) {
        mult_modp[i] = MulModPVar(INDEX_NUM_BITS);
        mult_modp[i].a <== adder_modp[i-1].out;
        mult_modp[i].b <== index;
        adder_modp[i] = AddModP();
        adder_modp[i].a <== mult_modp[i].out;
        adder_modp[i].b <== poly[DEGREE-1-i].f;
    }
    out <== adder_modp[DEGREE-1].out;
}

// Evaluates a polynomial mod P (= BabyJubJub ScalarField) at an index
template EvalPolyModP(DEGREE, INDEX) {
    assert(DEGREE >= 1);
    assert(INDEX > 0);
    input BabyJubJubScalarField() poly[DEGREE + 1];
    signal output out;

    if (INDEX == 1) {
        // Just add all the coefficients
        component adder_modp[DEGREE];
        adder_modp[0] = AddModP();
        adder_modp[0].a <== poly[0].f;
        adder_modp[0].b <== poly[1].f;

        for(var i = 1; i < DEGREE; i++) {
          adder_modp[i] = AddModP();
          adder_modp[i].a <== adder_modp[i-1].out;
          adder_modp[i].b <== poly[i+1].f;

        }
        out <== adder_modp[DEGREE-1].out;
    } else {
        // Use Horners rule
        component adder_modp[DEGREE];
        component mult_modp[DEGREE];

        mult_modp[0] = MulModP(INDEX);
        mult_modp[0].a <== poly[DEGREE].f;
        adder_modp[0] = AddModP();
        adder_modp[0].a <== mult_modp[0].out;
        adder_modp[0].b <== poly[DEGREE-1].f;

        for(var i = 1; i < DEGREE; i++) {
            mult_modp[i] = MulModP(INDEX);
            mult_modp[i].a <== adder_modp[i-1].out;
            adder_modp[i] = AddModP();
            adder_modp[i].a <== mult_modp[i].out;
            adder_modp[i].b <== poly[DEGREE-1-i].f;
        }
        out <== adder_modp[DEGREE-1].out;
    }
}

template KeyGenCommit(DEGREE) {
    // My secret key and public key
    signal input my_sk;
    signal output my_pk[2]; // Public
    // Coefficients of the sharing polynomial
    signal input poly[DEGREE + 1];
    // Commitments to the poly
    signal output comm_input_share[2]; // Public
    signal output comm_coeffs; // Public
    // Byproducts
    output BabyJubJubScalarField() poly_checked[DEGREE + 1];
    output BabyJubJubScalarField() sk_checked;

    ////////////////////////////////////////////////////////////////////////////
    // Range check the secret inputs
    ////////////////////////////////////////////////////////////////////////////

    // Range check my sk
    component sk_f = BabyJubJubIsInFr();
    sk_f.in <== my_sk;
    sk_checked <== sk_f.out;

    // Range check the coefficients
    // TODO Do i need this range checks for all the coefficients?
    component poly_f[DEGREE+1];
    for (var i=0; i<DEGREE+1; i++) {
        poly_f[i] = BabyJubJubIsInFr();
        poly_f[i].in <== poly[i];
        poly_checked[i] <== poly_f[i].out;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Recompute my public key
    ////////////////////////////////////////////////////////////////////////////

    component my_pk_comp = BabyJubJubScalarGenerator();
    my_pk_comp.e <== sk_f.out;
    my_pk[0] <== my_pk_comp.out.x;
    my_pk[1] <== my_pk_comp.out.y;

    ////////////////////////////////////////////////////////////////////////////
    // Recompute the commitments to the polynomial coefficients
    ////////////////////////////////////////////////////////////////////////////

    // The input_share
    component comm_share_comp = BabyJubJubScalarGenerator();
    comm_share_comp.e <== poly_f[0].out;
    comm_input_share[0] <== comm_share_comp.out.x;
    comm_input_share[1] <== comm_share_comp.out.y;

    // The coefficients in a poseidon sponge
    // Pad the inputs to a multiple of 3
    var NUM_POSEIDONS = (DEGREE + 2) \ 3;
    var poseidon_inputs[NUM_POSEIDONS][3];
    for (var i=0; i<NUM_POSEIDONS; i++) {
        for (var j=0; j<3; j++) {
            poseidon_inputs[i][j] = 0;
        }
    }
    for (var i=0; i<DEGREE; i++) {
        poseidon_inputs[i\3][i%3] = poly_f[i + 1].out.f;
    }

    // Finally the poseidon sponge
    component poseidon2_sponge[NUM_POSEIDONS];
    poseidon2_sponge[0] = Poseidon2(4);
    poseidon2_sponge[0].in[0] <== 391480396463803266015599265965237862; // Domain separator in capacity b"KeyGenPolyCoeff"
    poseidon2_sponge[0].in[1] <== poseidon_inputs[0][0];
    poseidon2_sponge[0].in[2] <== poseidon_inputs[0][1];
    poseidon2_sponge[0].in[3] <== poseidon_inputs[0][2];
    for (var i=1; i<NUM_POSEIDONS; i++) {
        poseidon2_sponge[i] = Poseidon2(4);
        poseidon2_sponge[i].in[0] <== poseidon2_sponge[i-1].out[0];
        poseidon2_sponge[i].in[1] <== poseidon2_sponge[i-1].out[1] + poseidon_inputs[i][0];
        poseidon2_sponge[i].in[2] <== poseidon2_sponge[i-1].out[2] + poseidon_inputs[i][1];
        poseidon2_sponge[i].in[3] <== poseidon2_sponge[i-1].out[3] + poseidon_inputs[i][2];
    }
    comm_coeffs <== poseidon2_sponge[NUM_POSEIDONS - 1].out[1];
}

// Encrypts the share with a derived symmetric key.
//
// The symmetric key is derived using DH with the provided secret-key and public-key. The public-key must be on the curve and in the correct subgroup, as this template does not perform any checks to verify these conditions.
template EncryptAndCommit() {
    // My secret key
    input BabyJubJubScalarField() my_sk;
    // The share to encrypt
    signal input share;
    // The other party's public key
    signal input pk[2]; // Public
    // Nonce used in the encryption of the shares
    signal input nonce; // Public
    // Outputs are the ciphertext and the commitment to the shares
    signal output ciphertext; // Public
    signal output comm_share[2]; // Public

    ////////////////////////////////////////////////////////////////////////////
    // Encrypt the share
    ////////////////////////////////////////////////////////////////////////////

    // Derive the symmetric keys for encryption
    BabyJubJubPoint() { twisted_edwards } pk_p;
    pk_p.x <== pk[0];
    pk_p.y <== pk[1];
    // Precondition: pk_p is on the curve and in the correct subgroup, guaranteed outside of the ZK proof as this is a public input.
    component sym_key = BabyJubJubScalarMul();
    sym_key.p <== pk_p;
    sym_key.e <== my_sk;

    // Encrypt the shares with the derived symmetric keys

    // From SAFE-API paper (https://eprint.iacr.org/2023/522.pdf)
    // Absorb 2, squeeze 1,  domainsep = 0x4142
    // [0x80000002, 0x00000001, 0x4142]
    var T1_DS = 0x80000002000000014142;
    var poseidon2_cipher_state[3] = Poseidon2(3)([T1_DS, sym_key.out.x, nonce]);
    ciphertext <== poseidon2_cipher_state[1] + share;

    ////////////////////////////////////////////////////////////////////////////
    // Commit to the share
    ////////////////////////////////////////////////////////////////////////////

    // No range check needed as share is computed to be in the prime field
    BabyJubJubScalarField() share_f;
    share_f.f <== share;
    component commit_comp = BabyJubJubScalarGenerator();
    commit_comp.e <== share_f;
    comm_share[0] <== commit_comp.out.x;
    comm_share[1] <== commit_comp.out.y;
}

template CheckDegree(MAX_DEGREE) {
    assert(MAX_DEGREE >= 1);
    signal input degree;
    // Coefficients of the sharing polynomial
    signal input poly[MAX_DEGREE + 1];

    // enforce: if degree < i then poly[i] == 0
    // We do this by constructing a signal should_be_zeros[i] which is 0 for i <= degree and 1 for i > degree
    // This is done by creating a one-hot vector of the degree (e.g., [0,0,1,0,0]) and translating it (e.g., to [0,0,0,1,1])
    component eq[MAX_DEGREE];
    signal equal[MAX_DEGREE + 1];
    signal should_be_zeros[MAX_DEGREE + 1];
    should_be_zeros[0] <== 0;
    equal[0] <== 0; // Because we disallow degree 0 later on
    for (var i = 1; i < MAX_DEGREE + 1; i++) {
        // Comparators
        eq[i-1] = IsEqual();
        eq[i-1].in[0] <== degree;
        eq[i-1].in[1] <== i;

        equal[i] <== eq[i-1].out;
        should_be_zeros[i] <== should_be_zeros[i-1] + equal[i - 1];

        // Constraint
        // if should_be_zeros[i] == 1 then poly[i] must be 0
        // if should_be_zeros[i] == 0 then poly[i] can be anything
        poly[i] * should_be_zeros[i] === 0;
    }

    // Enforce degree to be in 1..=MAX_DEGREE
    var sum = 0;
    for (var i = 1; i < MAX_DEGREE + 1; i++) {
        sum += equal[i];
    }
    sum === 1;

}

// Checks outside of the ZK proof: The public keys pks need to be valid BabyJubJub points in the correct subgroup.

template KeyGen(MAX_DEGREE, NUM_PARTIES) {
    assert(NUM_PARTIES >= 3);
    // The actual degree
    signal input degree; // Public
    // My secret key and public key
    signal input my_sk;
    signal output my_pk[2]; // Public
    // All parties' public keys
    signal input pks[NUM_PARTIES][2]; // Public
    // Coefficients of the sharing polynomial
    signal input poly[MAX_DEGREE + 1];
    // Nonces used in the encryption of the shares
    signal input nonces[NUM_PARTIES]; // Public
    // Commitments to the poly
    signal output comm_input_share[2]; // Public
    signal output comm_coeffs; // Public
    // Outputs are all the ciphertexts and the commitments to the shares
    signal output ciphertexts[NUM_PARTIES]; // Public
    signal output comm_shares[NUM_PARTIES][2]; // Public

    // Check that the coefficients beyond 'degree' are zero
    CheckDegree(MAX_DEGREE)(degree, poly);

    ////////////////////////////////////////////////////////////////////////////
    // Commit to the polynomial and my public key
    ////////////////////////////////////////////////////////////////////////////

    component keygen_commit = KeyGenCommit(MAX_DEGREE);
    keygen_commit.my_sk <== my_sk;
    keygen_commit.poly <== poly;
    my_pk <== keygen_commit.my_pk;
    comm_input_share <== keygen_commit.comm_input_share;
    comm_coeffs <== keygen_commit.comm_coeffs;

    ////////////////////////////////////////////////////////////////////////////
    // Derive the shares
    ////////////////////////////////////////////////////////////////////////////

    component derive_share[NUM_PARTIES];
    for (var i=0; i<NUM_PARTIES; i++) {
        derive_share[i] = EvalPolyModP(MAX_DEGREE, i + 1);
        // derive_share[i] = EvalPolyModPVar(MAX_DEGREE, 7);
        derive_share[i].poly <== keygen_commit.poly_checked;
        // derive_share[i].index <== i + 1;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Encrypt all the shares
    ////////////////////////////////////////////////////////////////////////////

    component derive_encrypt[NUM_PARTIES];
    for (var i=0; i<NUM_PARTIES; i++) {
        derive_encrypt[i] = EncryptAndCommit();
        derive_encrypt[i].my_sk <== keygen_commit.sk_checked;
        derive_encrypt[i].share <== derive_share[i].out;
        derive_encrypt[i].pk <== pks[i];
        derive_encrypt[i].nonce <== nonces[i];
        ciphertexts[i] <== derive_encrypt[i].ciphertext;
        comm_shares[i] <== derive_encrypt[i].comm_share;
    }
}

// component main {public [degree, pks, nonces]} = KeyGen(1, 3);
// component main {public [degree, pks, nonces]} = KeyGen(15, 30);
