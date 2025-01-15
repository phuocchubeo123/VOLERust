extern crate vole_rust;

use vole_rust::prg::PRG;
use std::time::Instant;
use std::ops::Mul;

fn main() {
    let mut prg = PRG::new(None, 0);

    // Test in-place random block generation
    let mut blocks = [[0u8; 16]; 5];
    prg.random_block(&mut blocks);
    println!("Random Blocks:");
    for (i, block) in blocks.iter().enumerate() {
        println!("Block {}: {:?}", i, block);
    }

    let start = Instant::now();

    // Test in-place random STARK-252 field elements generation
    let mut a = vec![Default::default(); 100000];
    prg.random_stark252_elements(&mut a);

    let duration = start.elapsed();
    println!("Time taken: {:?}", duration);

    let mut b = vec![Default::default(); 100000];
    prg.random_stark252_elements(&mut b);

    let start_mult = Instant::now();
    
    for (x, y) in a.iter().zip(b.iter()) {
        let c = x * y;
    }

    let duration_mult = start_mult.elapsed();
    println!("Time taken: {:?}", duration_mult);

    // println!("\nRandom STARK-252 Elements:");
    // for (i, elem) in elements.iter().enumerate() {
    //     println!("Element {}: {}", i, elem);
    // }
}
