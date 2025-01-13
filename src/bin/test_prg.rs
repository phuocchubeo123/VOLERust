extern crate vole_rust;

use vole_rust::prg::PRG;

fn main() {
    let mut prg = PRG::new(None, 0);

    // Test in-place random block generation
    let mut blocks = [[0u8; 16]; 5];
    prg.random_block(&mut blocks);
    println!("Random Blocks:");
    for (i, block) in blocks.iter().enumerate() {
        println!("Block {}: {:?}", i, block);
    }

    // Test in-place random STARK-252 field elements generation
    let mut elements = vec![Default::default(); 3];
    prg.random_stark252_elements(&mut elements);
    println!("\nRandom STARK-252 Elements:");
    for (i, elem) in elements.iter().enumerate() {
        println!("Element {}: {}", i, elem);
    }
}
