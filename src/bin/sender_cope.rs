extern crate vole_rust;
extern crate lambdaworks_math;

use std::net::TcpStream;
use vole_rust::socket_channel::TcpChannel;
use vole_rust::cope::Cope;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::traits::IsPrimeField;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Set up COPE
    let m = F::field_bit_size(); // Number of field elements
    let delta = FE::from(12345); // Arbitrary delta value
    let mut cope = Cope::new(0, &mut channel, m);

    // Initialize sender with delta
    cope.initialize_sender(delta);

    // Run the COPE protocol
    let result = cope.extend_sender();
    println!("COPE protocol result (sender): {:?}", result);

    // Prepare dummy data for the triple check
    let a = vec![delta];
    let b: Vec<FE> = (0..m).map(|i| FE::from(i as u64 + 1)).collect();

    // Run the consistency check
    cope.check_triple(&a, &b, m);
}
