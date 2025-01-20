extern crate vole_rust;

use vole_rust::iknp::IKNP;
use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use std::net::TcpListener;

fn main() {
    // Bind and wait for a connection from the sender
    let listener = TcpListener::bind("127.0.0.1:12345").expect("Failed to bind to address");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut io = TcpChannel::new(stream);

    let malicious = false; // Set to true if testing malicious mode
    let mut receiver = IKNP::new(&mut io, malicious);

    // Setup receiver
    receiver.setup_recv(None, None);

    // Prepare input choices
    let length = 1024; // Number of OTs to perform
    let choices: Vec<bool> = (0..length).map(|i| i % 2 == 0).collect(); // Alternating 0 and 1

    // Prepare output buffer
    let mut out = vec![[0u8; 16]; length];

    // Perform pre-computed OTs
    receiver.recv_pre(&mut out, &choices, length);

    println!("Receiver: Completed pre-computed OTs");
}