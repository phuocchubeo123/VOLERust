extern crate vole_rust;

use vole_rust::preot::OTPre;
use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use std::net::TcpListener;

fn main() {
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut io = TcpChannel::new(stream);

    let length = 10; // Number of messages
    let times = 1;   // Single round for simplicity

    let mut ot_receiver = OTPre::new(&mut io, length, times);

    // Precompute receiver data
    let data: Vec<[u8; 16]> = vec![[0x03; 16]; length];
    let choices: Vec<bool> = vec![true; length]; // Receiver's choices
    ot_receiver.recv_pre(&data, Some(&choices));

    // Send adjusted choice bits to the sender
    ot_receiver.choices_recver(&choices);

    // Receive the data
    let mut received_data: Vec<[u8; 16]> = vec![[0; 16]; length];
    ot_receiver.recv(&mut received_data, &choices, length, 0);

    println!("Received data: {:?}", received_data);
}