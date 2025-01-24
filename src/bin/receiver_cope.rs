extern crate vole_rust;
extern crate lambdaworks_math;
extern crate rand;
extern crate rand_chacha;

use std::net::{TcpListener, TcpStream};
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

    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Set up COPE
    let m = F::field_bit_size(); // Number of field elements
    let mut receiver_cope = Cope::new(1, m);

    // Receiver initializes
    receiver_cope.initialize_receiver(&mut channel);

    // Generate a random u
    let u = rand_field_element(&mut rng);
    println!("Receiver u: {}", u);

    // Test extend
    let single_result = receiver_cope.extend_receiver(&mut channel, u);
    receiver_cope.check_triple(&mut channel, &[u], &[single_result], 1);

    // // Test extend
    // let single_result = receiver_cope.extend_receiver(u);
    // receiver_cope.check_triple(&[u], &[single_result], 1);

    let start = Instant::now();

    // Test extend_batch
    let batch_size = 20000;
    let u_batch: Vec<FE> = (0..batch_size).map(|_| rand_field_element(&mut rng)).collect();
    let mut batch_result = vec![FE::zero(); batch_size];
    receiver_cope.extend_receiver_batch(&mut channel, &mut batch_result, &u_batch, batch_size);

    let duration = start.elapsed();
    println!("Time taken: {:?}", duration);

    receiver_cope.check_triple(&mut channel, &u_batch, &batch_result, batch_size);

}
