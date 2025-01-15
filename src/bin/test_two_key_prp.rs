extern crate vole_rust;
extern crate lambdaworks_math;

use vole_rust::two_key_prp::TwoKeyPRP;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    let keys_0 = [
        &[0u8; 16] as &[u8; 16],
        &[1u8; 16] as &[u8; 16],
        &[2u8; 16] as &[u8; 16],
        &[3u8; 16] as &[u8; 16],
    ];

    let keys_1 = [
        &[4u8; 16] as &[u8; 16],
        &[5u8; 16] as &[u8; 16],
        &[6u8; 16] as &[u8; 16],
        &[7u8; 16] as &[u8; 16],
    ];

    let twokeyprp = TwoKeyPRP::new(keys_0, keys_1);

    // Test `node_expand_1to2`
    let parent = FE::from(12345);
    let mut children_1to2 = [FE::zero(); 2];
    twokeyprp.node_expand_1to2(&mut children_1to2, &parent);

    println!("Test node_expand_1to2:");
    println!("Parent: {:?}", parent);
    println!("Children:");
    for child in &children_1to2 {
        println!("{:?}", child);
    }

    // Test `node_expand_2to4`
    let parents_2 = [FE::from(12345), FE::from(67890)];
    let mut children_2to4 = [FE::zero(); 4];
    twokeyprp.node_expand_2to4(&mut children_2to4, &parents_2);

    println!("\nTest node_expand_2to4:");
    println!("Parents: {:?}", parents_2);
    println!("Children:");
    for child in &children_2to4 {
        println!("{}", child);
    }

    // Test `node_expand_4to8`
    let parents_4 = [
        FE::from(12345),
        FE::from(67890),
        FE::from(11111),
        FE::from(22222),
    ];
    let mut children_4to8 = [FE::zero(); 8];
    twokeyprp.node_expand_4to8(&mut children_4to8, &parents_4);

    println!("\nTest node_expand_4to8:");
    println!("Parents: {:?}", parents_4);
    println!("Children:");
    for child in &children_4to8 {
        println!("{}", child);
    }

    // Benchmark `node_expand_1to2` for 10,000 iterations
    let mut parents = vec![FE::from(12345); 10_000];
    let mut children = vec![[FE::zero(); 2]; 10_000];

    let start = Instant::now();
    for i in 0..10_000 {
        twokeyprp.node_expand_1to2(&mut children[i], &parents[i]);
    }
    let duration = start.elapsed();

    println!(
        "\nBenchmark node_expand_1to2: Expanded 10,000 parents in {:?}",
        duration
    );
}
