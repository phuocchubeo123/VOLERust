extern crate vole_rust;
extern crate aes;
extern crate lambdaworks_math;

use vole_rust::two_key_prp::TwoKeyPRP;
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn test_node_expand_1to2() {
    let prp = TwoKeyPRP {};
    let parent = FE::from(12345u64); // Example parent field element
    let mut children = [FE::zero(), FE::zero()];

    prp.node_expand_1to2(&mut children, &parent);

    println!("Parent: {}", parent);
    println!("Child 1: {}", children[0]);
    println!("Child 2: {}", children[1]);
}

fn benchmark_node_expand_1to2() {
    let prp = TwoKeyPRP {};
    let parent = FE::from(12345u64); // Example parent field element
    let mut children = [FE::zero(), FE::zero()];
    let iterations = 1_000_000;

    let start = Instant::now();
    for _ in 0..iterations {
        prp.node_expand_1to2(&mut children, &parent);
    }
    let duration = start.elapsed();

    println!("Time taken for {} iterations: {:?}", iterations, duration);
}

fn main() {
    test_node_expand_1to2();
    benchmark_node_expand_1to2();
}
