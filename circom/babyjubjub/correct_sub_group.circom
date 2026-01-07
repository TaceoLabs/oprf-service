pragma circom 2.2.2;

include "babyjubjub.circom";

// Checks whether a given point in Twisted Edwards form is in the prime-order subgroup
// of BabyJubJub. The simplest way is to multiply the point by r, the characteristic
// (i.e., prime modulus) of the scalar field Fr, and check that the result is the identity.
//
// We reimplement SegmentMulAny from circomlib for this use case because we multiply
// by a fixed scalar (r), which circomlib does not provide directly. This saves
// roughly 922 constraints per check.
template BabyJubJubCheckInCorrectSubgroup() {
    input BabyJubJubPoint() { twisted_edwards } p;
    // Bit decomposition of Fr.
    var characteristic[251] = [1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1];

    // Multiply the point by Fr.
    signal out[2] <== EscalarMulFixScalar(characteristic)([p.x,p.y]);
    // We can construct the point without calling BabyJubJubCheck because
    // EscalarMulFixScalar always returns a point on the curve (or the identity element)
    // if the input to this signal is a valid point.
    BabyJubJubPoint() { twisted_edwards } result;
    result.x <== out[0];
    result.y <== out[1];

    // Assert that the resulting point is the identity element.
    BabyJubJubCheckIsIdentity()(result);
}


// Performs scalar multiplication e·P, where e is a fixed value in bit representation.
// In contrast to the standard library we hardcode the length of E to be 251
// (amount of bits needed to represent Fr). This helps during testing and makes the logic a bit simpler.
//
// We have two segments, the first is 148 bits long and the second 103 bits.
// We chose this segment size to mirror the segment sizes in the standard library.
//
template EscalarMulFixScalar(E) {
    // check that we have at least 251 bits by accessing this 251st element. This will fail if we have less bits.
    assert(E[250] == E[250]);
    signal input p[2];              // Point (Twisted format)
    signal output out[2];           // Point (Twisted format)

    // check if point is identity (0,1)
    signal x_is_zero <== IsZero()(p[0]);
    signal y_is_one <== IsZero()(p[1]-1);
    // since x_is_zero and y_is_one can only be 0/1, this can also only be 0/1 and is the AND of both
    signal is_identity <== x_is_zero * y_is_one;

    // first segment
    var bits1[148];
    for (var i=0;i<148;i++) {
        bits1[i] = E[i];
    }

    // if x is zero, we bind to the generator
    signal in_x <== p[0] + (5299619240641551281634865583518297030282874472190772894086521144482721001553 - p[0])*is_identity;
    signal in_y <== p[1] + (16950150798460657717958625567821834550301663161624707787222815936182638968203 - p[1])*is_identity;

    signal (s1_out[2], s1_dbl[2]) <== SegmentMulFixScalar(bits1,148)([in_x, in_y]);

    // second segment
    var bits2[103];
    for (var i=0;i<103;i++) {
        bits2[i] = E[148 + i];
    }

    signal dbl[2] <== MontgomeryDouble()(s1_dbl);
    signal m2e[2] <== Montgomery2Edwards()(dbl);
    signal (s2_out[2], s2_dbl[2]) <== SegmentMulFixScalar(bits2, 103)(m2e);

    signal (x_out, y_out) <== BabyAdd()(s1_out[0], s1_out[1], s2_out[0], s2_out[1]);

    out[0] <== x_out * (1 - is_identity); // 0 if is_identity == 1, x_out if is_identity == 0
    out[1] <== y_out + (1 - y_out) * is_identity; // 1 if is_identity == 1, y_out if is_identity == 0
}

// Small rewrite of BitElementMulAny from the Circom standard library. Takes two points
// in Montgomery form and a hardcoded bit. Unlike the standard-library version, the
// selector is known at compile time. Therefore, we can skip multiplexing and simply
// conditionally add on top of the doubling.
template BitElementMulFixScalar(bit) {
    assert(bit == 0 || bit == 1);
    signal input dbl_in[2];
    signal input add_in[2];
    signal output dbl_out[2];
    signal output add_out[2];

    dbl_out <== MontgomeryDouble()(dbl_in);
    if (bit == 1) {
        add_out <== MontgomeryAdd()(dbl_out, add_in);
    } else {
        // No addition needed; just forward the input.
        add_out <== add_in;
    }
}


// Performs segment multiplication as defined in the BabyJubJub paper with a fixed E.
// E is a bit segment of length n from the larger scalar. We require n because we can't
// otherwise know the length of E. All bits after n will be ignored.
//
// In contrast to other SegmentMul implementations, we can skip some MontgomeryAdds and
// multiplexing because we know the selectors at compile time.
//
// Inspired by SegmentMulAny from the standard library. We leave the implementation as-is
// to remain consistent with the standard library.
template SegmentMulFixScalar(E,n) {
    signal input p[2];
    signal output out[2];
    signal output dbl[2];

    component bits[n-1];

    // we also forbid all points that do not have a valid mapping to Montgomery form (x = 0 or y = 1)
    // this is needed because we allow the correct subgroup check to be called on any point on the curve, such as the two-torsion point, which does not have a valid mapping to Montgomery form
    // since it is also not a valid point in the prime-order subgroup, failing these assertions here is intended
    signal is_x_zero <== IsZero()(p[0]);
    is_x_zero === 0;
    signal is_y_one <== IsZero()(p[1]-1);
    is_y_one === 0;

    component e2m = Edwards2Montgomery();

    p[0] ==> e2m.in[0];
    p[1] ==> e2m.in[1];

    bits[0] = BitElementMulFixScalar(E[1]);
    e2m.out[0] ==> bits[0].dbl_in[0];
    e2m.out[1] ==> bits[0].dbl_in[1];
    e2m.out[0] ==> bits[0].add_in[0];
    e2m.out[1] ==> bits[0].add_in[1];

    for (var i=1; i<n-1; i++) {
        bits[i] = BitElementMulFixScalar(E[i+1]);

        bits[i-1].dbl_out[0] ==> bits[i].dbl_in[0];
        bits[i-1].dbl_out[1] ==> bits[i].dbl_in[1];
        bits[i-1].add_out[0] ==> bits[i].add_in[0];
        bits[i-1].add_out[1] ==> bits[i].add_in[1];
    }

    bits[n-2].dbl_out[0] ==> dbl[0];
    bits[n-2].dbl_out[1] ==> dbl[1];

    component m2e = Montgomery2Edwards();

    bits[n-2].add_out[0] ==> m2e.in[0];
    bits[n-2].add_out[1] ==> m2e.in[1];

    if (E[0] == 1) {
        out <== m2e.out;
    } else {
        signal (bba_x, bba_y) <== BabyAdd()(m2e.out[0],m2e.out[1], -p[0], p[1]);
        out <== [bba_x, bba_y];
    }
}
