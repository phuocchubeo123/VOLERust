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
    let mut sender_cot = BaseCot::new(0, false);

    // Set up the sender's precomputation phase
    sender_cot.cot_gen_pre(&mut channel, None);

    // Original COT generation
    const depth: usize = 4;
    let size = depth - 1; // Number of COTs
    let times = 1;
    // New COT generation using OTPre
    let mut sender_pre_ot = OTPre::new(size, times);
    sender_cot.cot_gen_preot(&mut channel, &mut sender_pre_ot, size*times, None);

    let mut ggm_tree_mem = [FE::zero(); 1 << (depth - 1)];
    let delta = rand_field_element();
    let gamma = rand_field_element();

    channel.send_stark252(&[delta.clone(), gamma.clone()]).expect("Failed to send delta and gamma");

    // Initialize Spfss for the sender
    let mut sender_spfss = SpfssSenderFp::new(depth);

    sender_pre_ot.choices_sender(&mut channel);

    sender_spfss.compute(&mut ggm_tree_mem, delta, gamma);
    sender_spfss.send(&mut channel, &mut sender_pre_ot, 0);

    println!("GGM tree:");
    for ggm in ggm_tree_mem.iter() {
        println!("{:?}", ggm);
    }

    println!("Current: {:?}", gamma - ggm_tree_mem[(1 << (depth - 1)) - 1]);

    sender_spfss.consistency_check(&mut channel, gamma);
}