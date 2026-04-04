use super::constants::DS_C_CS;
use poseidon2::bn254::perm;

pub(crate) fn generate_message(mt_index: Field, query: Field) -> Field {
    let state = perm::x5_3([DS_C_CS, mt_index, query]);
    state[1]
}
