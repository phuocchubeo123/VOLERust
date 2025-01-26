extern crate vole_rust; 
extern crate lambdaworks_math;
extern crate rand;

use vole_rust::spfss_receiver::SpfssRecverFp;
use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use vole_rust::base_cot::BaseCot;
use vole_rust::preot::OTPre;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use std::net::TcpListener;
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

    // Initialize BaseCot for the receiver (BOB)
    let mut receiver_cot = BaseCot::new(1, false);

    // Set up the receiver's precomputation phase
    receiver_cot.cot_gen_pre(&mut channel, None);

    // Original COT generation
    const depth: usize = 4;
    let size = depth - 1; // Number of COTs
    let times = 1;
    let mut choice_bits = vec![false; size*times];
    // Populate random choice bits
    for bit in &mut choice_bits {
        *bit = rand::random();
    }

    // New COT generation using OTPre
    let mut receiver_pre_ot = OTPre::new(size, times);
    receiver_cot.cot_gen_preot(&mut channel, &mut receiver_pre_ot, size*times, Some(&choice_bits));

    let mut ggm_tree_mem = [FE::zero(); 1 << (depth - 1)];
    let beta = rand_field_element();
    let received_data = channel.receive_stark252(2).expect("Failed to receive delta and gamma");
    let delta = received_data[0];
    let gamma = received_data[1];
    let delta2 = gamma + delta * beta;

    // Initialize Spfss for the sender
    let mut receiver_spfss = SpfssRecverFp::new(depth);

    receiver_pre_ot.choices_recver(&mut channel, &[false; depth - 1]);

    receiver_spfss.recv(&mut channel, &mut receiver_pre_ot, 0);
    receiver_spfss.compute(&mut ggm_tree_mem, delta2);

    println!("GGM tree:");
    for ggm in ggm_tree_mem.iter() {
        println!("{:?}", ggm);
    }

    println!("Test delta: {:?}", delta);
    println!("Manual consistency check: {:?}", ggm_tree_mem[(1<<(depth-1))-1] - delta * beta);

    receiver_spfss.consistency_check(&mut channel, delta2, beta);
}