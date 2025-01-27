// In this program:
// 1. Benchmark time to create 100_000 new Aes128 key: about 5 ms 

extern crate aes;
use aes::Aes128;
use aes::cipher::KeyInit;
use std::time::Instant;
use aes::Block;

fn bench_create_key() {
    // Define two keys for testing
    let key1 = [0u8; 16];
    let key2 = [1u8; 16];

    // Variables to store the elapsed times
    let mut rekey_time = 0;
    let mut new_key_time = 0;

    // Benchmark rekeying 100,000 times
    let mut cipher = Aes128::new(&key1.into());
    let start_rekey = Instant::now();
    for _ in 0..100_000 {
        cipher = Aes128::new(&key2.into()); // Rekey
    }
    rekey_time = start_rekey.elapsed().as_millis();

    // Benchmark creating a new AES key 100,000 times
    let start_new_key = Instant::now();
    for _ in 0..100_000 {
        let _new_cipher = Aes128::new(&key2.into()); // Create new key
    }
    new_key_time = start_new_key.elapsed().as_millis();

    // Print results
    println!("Benchmark Results:");
    println!("Rekeying 100,000 times took: {} ms", rekey_time);
    println!("New key initialization 100,000 times took: {} ms", new_key_time);
}

fn bench_block_encrypt() {

}

fn main() {
    bench_create_key();
}
