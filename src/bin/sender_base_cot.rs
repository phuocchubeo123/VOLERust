extern crate vole_rust;

use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use vole_rust::base_cot::BaseCot;
use vole_rust::preot::OTPre;
use std::net::TcpStream;

fn main() {
    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Initialize BaseCot for the sender (ALICE)
    let mut sender_cot = BaseCot::new(0, false);

    // Set up the sender's precomputation phase
    sender_cot.cot_gen_pre(&mut channel, None);

    // Original COT generation
    let size = 512; // Number of COTs
    let mut original_ot_data = vec![[0u8; 32]; size];
    sender_cot.cot_gen(&mut channel, &mut original_ot_data, size, None);

    // Print the original COT data
    println!("Sender Original COT data:");
    for (i, block) in original_ot_data.iter().enumerate().take(5) {
        println!("Block {}: {:?}", i, block);
    }

    // Check correctness of the original COT data
    let is_original_valid = sender_cot.check_cot(&mut channel, &original_ot_data, size);
    println!("Original COT validation result: {}", is_original_valid);

        // New COT generation using OTPre
    let mut sender_pre_ot = OTPre::new(size, 1);
    sender_cot.cot_gen_preot(&mut channel, &mut sender_pre_ot, size, None);

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
}
