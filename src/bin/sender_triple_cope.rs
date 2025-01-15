extern crate vole_rust;
extern crate lambdaworks_math;
extern crate rand;
extern crate rand_chacha;

use std::net::TcpStream;
use vole_rust::socket_channel::TcpChannel;
use vole_rust::comm_channel::CommunicationChannel;
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

    // Generate delta and c
    let mut rng = rand::thread_rng();
    let delta = rand_field_element(&mut rng);
    let c = rand_field_element(&mut rng);

    // Generate a and b using the relationship: b = a * delta + c
    let a = rand_field_element(&mut rng);
    let b = a * delta + c;

    println!("Sender values:");
    println!("Delta: {}", delta);
    println!("A: {}", a);
    println!("B: {}", b);
    println!("C: {}", c);

    // Send a and b to receiver
    channel.send_stark252(&[a]).expect("Failed to send `a`");
    channel.send_stark252(&[b]).expect("Failed to send `b`");

    // Set up COPE
    let m = F::field_bit_size(); // Number of field elements
    let mut sender_cope = Cope::new(0, &mut channel, m);


    // Perform the check
    sender_cope.check_triple(&[delta], &[c], 1);
}