extern crate vole_rust;
extern crate lambdaworks_math;
extern crate rand;

use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use vole_rust::spfss_sender::SpfssSenderFp;
use vole_rust::preot::OTPre;
use vole_rust::base_cot::BaseCot;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use std::net::TcpStream;
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

    // Initialize BaseCot for the sender (ALICE)
    let mut sender_cot = BaseCot::new(0, &mut channel, false);

    // Set up the sender's precomputation phase
    sender_cot.cot_gen_pre(None);

    // Original COT generation
    let size = 512; // Number of COTs
    // New COT generation using OTPre
    let mut sender_pre_ot = OTPre::new(size, 1);
    sender_cot.cot_gen_preot(&mut sender_pre_ot, size, None);

    // Send data using OTPre
    let mut m0 = vec![[0u8; 32]; size];
    let mut m1 = vec![[0u8; 32]; size];
    for i in 0..size {
        m0[i] = [i as u8; 32];
        m1[i] = [(i + 1) as u8; 32];
    }

    for (i, block) in m0.iter().enumerate().take(5) {
        println!("Block {} of m0: {:?}", i, block);
    }

    for (i, block) in m1.iter().enumerate().take(5) {
        println!("Block {} of m1: {:?}", i, block);
    }

    sender_pre_ot.send(&mut channel, &m0, &m1, size, 0);
    println!("Sender sent data using OTPre::send()");

    const depth: usize = 4;
    let mut ggm_tree_mem = [FE::zero(); 1 << (depth - 1)];
    let delta = rand_field_element();
    let gamma = rand_field_element();

    // Initialize Spfss for the sender
    let mut sender_spfss = SpfssSenderFp::new(&mut channel, depth);
    sender_spfss.compute(&mut ggm_tree_mem, delta, gamma);
    sender_spfss.send(&mut sender_pre_ot, 0);

    println!("GGM Tree: {:?}", ggm_tree_mem);
}
