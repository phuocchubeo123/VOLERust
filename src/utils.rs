use lambdaworks_math::{
    fft::cpu::{bit_reversing::in_place_bit_reverse_permute, roots_of_unity::get_twiddles},
    field::{
        element::FieldElement, fields::fft_friendly::stark_252_prime_field::Stark252PrimeField,
        traits::RootsConfig,
    },
    polynomial::Polynomial,
    unsigned_integer::element::UnsignedInteger,
};
use rand::{random, RngCore};

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub fn rand_field_element(rng: &mut dyn rand::RngCore) -> FE {
    let rand_big = UnsignedInteger { limbs: random(&mut rng) };
    FE::new(rand_big)
}