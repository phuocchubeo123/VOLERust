extern crate vole_rust;
extern crate lambdaworks_math;
extern crate rand;
extern crate rand_chacha;

use std::net::TcpStream;
use std::time::Instant;
use vole_rust::socket_channel::TcpChannel;
use vole_rust::cope::Cope;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::traits::IsPrimeField;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use rand::{RngCore, random, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub fn rand_field_element(rng: &mut dyn rand::RngCore) -> FE {
    let rand_big = UnsignedInteger { limbs: random() };
    FE::new(rand_big)
}

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Set up COPE
    let m = F::field_bit_size(); // Number of field elements
    let mut sender_cope = Cope::new(0, &mut channel, m);

    // Generate a random delta
    let delta = rand_field_element(&mut rng);
    println!("Sender delta: {}", delta);

    // Sender initializes with delta
    sender_cope.initialize_sender(delta);

    // Test extend
    let single_result = sender_cope.extend_sender();
    sender_cope.check_triple(&[delta], &[single_result], 1);

    // // Test extend
    // let single_result = sender_cope.extend_sender();
    // sender_cope.check_triple(&[delta], &[single_result], 1);

    let start = Instant::now();

    // Test extend_batch
    let batch_size = 100;
    let mut batch_result = vec![FE::zero(); batch_size];
    sender_cope.extend_sender_batch(&mut batch_result, batch_size);

    let duration = start.elapsed();
    println!("Time taken: {:?}", duration);

    sender_cope.check_triple(&[delta], &batch_result, batch_size);

}
