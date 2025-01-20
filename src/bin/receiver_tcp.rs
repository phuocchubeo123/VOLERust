extern crate vole_rust;
extern crate lambdaworks_math;

use std::net::{TcpListener, TcpStream};
use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    let element_count = 100_000; // Number of elements to receive

    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Benchmark receive_stark252
    let start = Instant::now();
    let elements = channel
        .receive_stark252(element_count)
        .expect("Failed to receive elements");
    let duration = start.elapsed();

    println!("Received {} elements in {:?}", elements.len(), duration);

    // Receive the bits
    let received_bits = channel.receive_bits().expect("Failed to receive bits");

    println!("Receiver: Received bits: {:?}", received_bits);
    println!("Receiver: Bits received successfully.");
}
