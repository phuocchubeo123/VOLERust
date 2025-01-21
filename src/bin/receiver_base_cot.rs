extern crate vole_rust;

use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use vole_rust::base_cot::BaseCot;
use vole_rust::preot::OTPre;
use std::net::TcpListener;

fn main() {
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to address");
    println!("Waiting for sender...");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Initialize BaseCot for the receiver (BOB)
    let mut receiver_cot = BaseCot::new(1, &mut channel, false);

    // Set up the receiver's precomputation phase
    receiver_cot.cot_gen_pre(None);

    // Original COT generation
    let size = 128; // Number of COTs
    let mut original_ot_data = vec![[0u8; 16]; size];
    let mut choice_bits = vec![false; size];

    // Populate random choice bits
    for bit in &mut choice_bits {
        *bit = rand::random();
    }

    receiver_cot.cot_gen(&mut original_ot_data, size, Some(&choice_bits));

    // Print the original COT data
    println!("Receiver Original COT data:");
    for (i, block) in original_ot_data.iter().enumerate().take(5) {
        println!("Block {}: {:?}", i, block);
    }

    println!("Choice bits: {:?}", &choice_bits[..5]);

    // Check correctness of the original COT data
    let is_original_valid = receiver_cot.check_cot(&original_ot_data, size);
    println!("Original COT validation result: {}", is_original_valid);

        // New COT generation using OTPre
    let mut receiver_pre_ot = OTPre::new(size, 1);
    receiver_cot.cot_gen_preot(&mut receiver_pre_ot, size, Some(&choice_bits));

    // Receive data using OTPre
    let mut received_data = vec![[0u8; 16]; size];
    receiver_pre_ot.recv(&mut channel, &mut received_data, &choice_bits, size, 0);

    println!("Choice bits: {:?}", &choice_bits[..5]);

    println!("Receiver received data using OTPre::recv:");
    for (i, block) in received_data.iter().enumerate().take(5) {
        println!("Received Block {}: {:?}", i, block);
    }
}
