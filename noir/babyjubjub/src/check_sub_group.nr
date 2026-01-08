use super::{BabyJubJubPoint, montgomery::MontgomeryPoint};

fn bit_element_mul_fix_scalar(
    bit: u1,
    dbl_in: MontgomeryPoint,
    add_in: MontgomeryPoint,
) -> (MontgomeryPoint, MontgomeryPoint) {
    // assert((bit == 0) | (bit == 1), "Bit must be 0 or 1 in fixed-scalar step"); // given by data type

    let dbl_out = dbl_in.double();

    let add_out = if bit == 1 {
        dbl_out.add(add_in)
    } else {
        add_in
    };

    (dbl_out, add_out)
}

fn segment_mul_fix_scalar<let N: u32>(
    bits: [u1; N],
    base: BabyJubJubPoint,
) -> (BabyJubJubPoint, MontgomeryPoint) {
    assert(N >= 2, "Segment size must be >= 2 bits");
    assert(N <= 246, "Segment size must be <= 246 bits to avoid overflow");

    assert(base.x != 0, "Base x cannot be zero for fixed-scalar multiplication");
    assert(base.y != 1, "Base y cannot be 1 for fixed-scalar multiplication");
    // Precondition: base has a valid montgomery representation (i.e., not y == 1 or x == 0)
    let base_mont = base.to_montgomery();

    let mut dbl_current = base_mont;
    let mut add_current = base_mont;

    for i in 1..(N as u32) {
        let (dbl_next, add_next) = bit_element_mul_fix_scalar(bits[i], dbl_current, add_current);
        dbl_current = dbl_next;
        add_current = add_next;
    }

    let dbl_out_montgomery = dbl_current;

    // Convert back to Edwards form
    // Precondition is satisfied as the segment size is chosen to avoid overflows being possible,
    // therefore we arrive at a valid Montgomery point here
    let add_edwards = BabyJubJubPoint::from_montgomery(add_current);

    let result_minus_base = add_edwards.subtract(base);

    let bit0 = bits[0] as Field;
    let final_x = (add_edwards.x - result_minus_base.x) * bit0 + result_minus_base.x;
    let final_y = (add_edwards.y - result_minus_base.y) * bit0 + result_minus_base.y;
    let result = BabyJubJubPoint { x: final_x, y: final_y };

    (result, dbl_out_montgomery)
}

// Fixed-base scalar multiplication for arbitrary BabyJubJub base point
// Uses Montgomery curve representation internally for efficiency
// Precondition: base point is on the curve
pub fn esc_mul_fix_scalar(bits: [u1; 251], base: BabyJubJubPoint) -> BabyJubJubPoint {
    let mut bits1: [u1; 148] = [0; 148];
    for i in 0..148 {
        bits1[i] = bits[i];
    }

    let mut bits2: [u1; 103] = [0; 103];
    for i in 0..103 {
        bits2[i] = bits[148 + i];
    }

    let is_zero_point = base.is_identity();
    let base_for_seg0 = if is_zero_point {
        BabyJubJubPoint::generator()
    } else {
        base
    };

    let (s1_out, s1_dbl) = segment_mul_fix_scalar(bits1, base_for_seg0);

    let dbl = s1_dbl.double();
    let base_seg1 = BabyJubJubPoint::from_montgomery(dbl);

    let (s2_out, _) = segment_mul_fix_scalar(bits2, base_seg1);

    let combined = s1_out.add(s2_out);

    let out_x = if is_zero_point { 0 } else { combined.x };
    let out_y = if is_zero_point { 1 } else { combined.y };

    BabyJubJubPoint { x: out_x, y: out_y }
}

#[test]
fn test_babyjubjub_in_correct_subgroup() {
    let p0 = 4597297048474520994314398800947075450541957920804155712178316083765998639288;
    let p1 = 5569132826648062501012191259106565336315721760204071234863390487921354852142;

    assert(BabyJubJubPoint::check_sub_group(BabyJubJubPoint::new(p0, p1)));
}

#[test(should_fail)]
fn test_two_torsion_not_correct_subgroup() {
    let p0 = 0;
    let p1 = -1;

    assert(BabyJubJubPoint::check_sub_group(BabyJubJubPoint::new(p0, p1)));
}
