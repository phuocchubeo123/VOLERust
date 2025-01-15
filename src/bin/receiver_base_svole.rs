extern crate vole_rust;
extern crate lambdaworks_math;
extern crate rand;
extern crate rand_chacha;

use std::net::TcpListener;
use std::time::Instant;
use vole_rust::socket_channel::TcpChannel;
use vole_rust::base_svole::BaseSvole;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use rand::random;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub fn rand_field_element() -> FE {
    let rand_big = UnsignedInteger { limbs: random() };
    FE::new(rand_big)
}

fn main() {
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to address");
    println!("Waiting for sender...");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Set up BaseSvole
    let mut receiver_svole = BaseSvole::new_receiver(&mut channel);

    // Test triple generation
    let batch_size = 20000;
    let mut shares = vec![FE::zero(); batch_size];
    let u_batch: Vec<FE> = (0..batch_size).map(|_| rand_field_element()).collect();

    let start = Instant::now();

    receiver_svole.triple_gen_recv(&mut shares, &u_batch, batch_size);

    let duration = start.elapsed();
    println!("Triple generation (recv) time: {:?}", duration);
}
