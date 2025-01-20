extern crate vole_rust;

use vole_rust::iknp::IKNP;
use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use std::net::TcpStream;

fn main() {
    // Establish connection to the receiver
    let stream = TcpStream::connect("127.0.0.1:12345").expect("Failed to connect to receiver");
    let mut io = TcpChannel::new(stream);

    let malicious = false; // Set to true if testing malicious mode
    let mut sender = IKNP::new(&mut io, malicious);

    // Setup sender
    sender.setup_send(None, None);

    // Prepare output buffer
    let length = 1024; // Number of OTs to perform
    let mut out = vec![[0u8; 16]; length];

    // Perform pre-computed OTs
    sender.send_pre(&mut out, length);

    println!("Sender: Completed pre-computed OTs");
}
