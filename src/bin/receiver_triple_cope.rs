extern crate vole_rust;
extern crate lambdaworks_math;
extern crate rand;
extern crate rand_chacha;

use std::net::{TcpListener, TcpStream};
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

    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Receive a and b from sender
    let a = channel
        .receive_stark252(1)
        .expect("Failed to receive `a`")[0];
    let b = channel
        .receive_stark252(1)
        .expect("Failed to receive `b`")[0];

    // Set up COPE
    let m = F::field_bit_size(); // Number of field elements
    let mut receiver_cope = Cope::new(1, m);

    println!("Receiver values:");
    println!("A: {}", a);
    println!("B: {}", b);

    // // Generate a random delta (to simulate receiver-side delta) and calculate c
    // let delta = receiver_cope
    //     .io
    //     .receive_stark252(1)
    //     .expect("Failed to receive `delta` in check_triple")[0];
    // let c = b - a * delta;

    // Perform the check
    receiver_cope.check_triple(&mut channel, &[a], &[b], 1);
}
