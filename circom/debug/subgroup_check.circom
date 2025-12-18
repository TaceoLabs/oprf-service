pragma circom 2.2.0;
include "babyjubjub/correct_sub_group.circom";

template Wrapper() {
    signal input x;
    signal input y;
    BabyJubJubPoint() { twisted_edwards } p;
    p.x <== x;
    p.y <== y;
    BabyJubJubCheckInCorrectSubgroup()(p);
}

component main = Wrapper();
