pragma circom 2.2.2;

include "babyjubjub.circom";
include "circomlib/babyjub.circom";

// Checks whether a given point in Twisted Edwards form is in the prime-order subgroup
// of BabyJubJub. The simplest way is to multiply the point by r, the characteristic
// (i.e., prime modulus) of the scalar field Fr, and check that the result is the identity.
// Precondition: the input point is required to be on the BabyJubJub curve.
//
// We use a simple double and add ladder for this implementation since the scalar is fixed.
template BabyJubJubCheckInCorrectSubgroup() {
    input BabyJubJubPoint() { twisted_edwards } p;
    // Bit decomposition of Fr.
    var characteristic[251] = [1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1];

    component bitmuls[250];

    // ensure the highest bit is set
    // we can therefore start with accumulator = P
    assert(characteristic[250] == 1);


    for (var i = 249; i >= 0; i--) {
        bitmuls[i] = BitElementTeMulFixSclalar(characteristic[i]);
        bitmuls[i].add_in[0] <== p.x;
        bitmuls[i].add_in[1] <== p.y;
        if (i == 249) {
            bitmuls[i].dbl_in[0] <== p.x;
            bitmuls[i].dbl_in[1] <== p.y;
        } else {
            bitmuls[i].dbl_in[0] <== bitmuls[i+1].out[0];
            bitmuls[i].dbl_in[1] <== bitmuls[i+1].out[1];
        }
    }
    BabyJubJubPoint() { twisted_edwards } result;

    result.x <== bitmuls[0].out[0];
    result.y <== bitmuls[0].out[1];

    // Assert that the resulting point is the identity element.
    BabyJubJubCheckIsIdentity()(result);
}

template BitElementTeMulFixSclalar(bit) {
    assert(bit == 0 || bit == 1);
    signal input dbl_in[2];
    signal input add_in[2];
    signal output out[2];

    component dbl = BabyDbl();
    dbl.x <== dbl_in[0];
    dbl.y <== dbl_in[1];

    if (bit == 1) {
        component add = BabyAdd();
        add.x1 <== dbl.xout;
        add.y1 <== dbl.yout;
        add.x2 <== add_in[0];
        add.y2 <== add_in[1];
        out[0] <== add.xout;
        out[1] <== add.yout;
    } else {
        out[0] <== dbl.xout;
        out[1] <== dbl.yout;
    }
}
