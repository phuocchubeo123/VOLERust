extern crate vole_rust;
extern crate lambdaworks_math;

use std::net::{TcpListener, TcpStream};
use vole_rust::socket_channel::TcpChannel;
use vole_rust::cope::Cope;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::traits::IsPrimeField;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Set up COPE
    let m = F::field_bit_size(); // Number of field elements
    let mut cope = Cope::new(1, &mut channel, m);

    // Initialize receiver
    cope.initialize_receiver();

    // Prepare dummy data for the triple check
    let a = FE::zero(); // Placeholder; not used in the receiver for the check
    let b: Vec<FE> = (0..m).map(|i| FE::from(i as u64 + 1)).collect();

    // Run the COPE protocol
    let u = FE::from(54321); // Arbitrary field element
    let result = cope.extend_receiver(u);
    println!("COPE protocol result (receiver): {:?}", result);

    // Run the consistency check
    cope.check_triple(&[a], &b, m);
}
