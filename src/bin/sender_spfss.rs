extern crate vole_rust;
extern crate lambdaworks_math;

use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use vole_rust::spfss::SpfssSenderFp;
use vole_rust::ot::OTPre;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use std::net::TcpStream;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Initialize SpfssSenderFp
    let depth = 10; // Example depth of GGM tree
    let mut sender = SpfssSenderFp::new(&mut channel, depth);

    // Initialize OTPre
    let mut pre_ot = OTPre::new(&mut channel, depth, 1);
    pre_ot.reset();

    // Example secret and gamma values
    let secret_share_x = FE::from(42u64);
    let triple_yz = FE::from(7u64);

    let mut ggm_tree_mem = vec![FE::zero(); 1 << (depth - 1)];
    sender.compute(&mut ggm_tree_mem, secret_share_x, triple_yz);

    // Oblivious Transfer (OT) functionality
    let ot = |msg0: &[[u8; 16]], msg1: &[[u8; 16]], size: usize| {
        pre_ot.send(msg0, msg1, size, 0);
    };

    sender.send(&mut ot, 0);
    channel.flush().expect("Failed to flush sender channel");

    println!("Sender successfully completed SPFSS!");
}
