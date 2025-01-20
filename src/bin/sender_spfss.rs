extern crate vole_rust; 
extern crate lambdaworks_math;

use vole_rust::spfss_sender::SpfssSenderFp;
use vole_rust::socket_channel::TcpChannel; 
use vole_rust::prg::PRG;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    let depth = 5; // Depth of the GGM tree
    let leave_n = 1 << (depth - 1);

    // Connect to the receiver
    let stream = std::net::TcpStream::connect("127.0.0.1:8080")
        .expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Initialize the sender
    let mut sender = SpfssSenderFp::new(&mut channel, depth);

    // Simulated secret and gamma
    let secret = FE::from(42u64); // Example secret
    let gamma = FE::from(17u64);  // Example gamma

    // Compute the GGM tree
    let mut ggm_tree_mem = vec![FE::zero(); leave_n];
    sender.compute(&mut ggm_tree_mem, secret.clone(), gamma.clone());

    println!("Sender completed successfully!");
}
