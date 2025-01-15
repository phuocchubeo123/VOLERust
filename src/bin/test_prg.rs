extern crate lambdaworks_math;
extern crate rand;
extern crate aes;
extern crate vole_rust;

use vole_rust::prg::PRG;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Number of Stark252 elements to generate
    let count = 100_000;

    // Initialize the PRG with a random seed and ID
    let seed = [0u8; 16]; // Replace with a specific seed if needed
    let id = 42; // Example ID for reseeding
    let mut prg = PRG::new(Some(&seed), id);

    // Allocate space for the elements
    let mut elements = vec![FE::zero(); count];

    println!("Benchmarking PRG for generating {} Stark252 elements...", count);

    // Benchmark the generation process
    let start = Instant::now();
    prg.random_stark252_elements(&mut elements);
    let duration = start.elapsed();

    println!(
        "Generated {} Stark252 elements in {:?}",
        count, duration
    );
}
