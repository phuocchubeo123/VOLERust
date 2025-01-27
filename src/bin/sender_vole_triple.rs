extern crate vole_rust;
extern crate lambdaworks_math;
extern crate rand;

use vole_rust::socket_channel::TcpChannel;
use vole_rust::vole_triple::{FP_DEFAULT, VoleTriple, PHUOC_LPN};
use std::net::TcpStream;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::traits::IsPrimeField;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use rand::random;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub fn rand_field_element() -> FE {
    let rand_big = UnsignedInteger { limbs: random() };
    FE::new(rand_big)
}

fn main() {
    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    let mut vole = VoleTriple::new(0, false, &mut channel, PHUOC_LPN);

    let delta = rand_field_element();
    vole.setup_sender(&mut channel, delta);

    vole.extend_initialization();

    const size: usize = 1000;
    let mut y = [FE::zero(); size];
    let mut z = [FE::zero(); size];
    vole.extend(&mut channel, &mut y, &mut z, size);
}