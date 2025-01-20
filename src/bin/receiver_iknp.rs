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

    let mut receiver_iknp = IKNP::new(&mut io, true);
    receiver_iknp.setup_recv(None, None);

    let length = 2048;
    let mut data = vec![[0u8; 16]; length];
    let r = vec![true; length]; // Example choice bits

    receiver_iknp.recv_cot(&mut data, &r, length);

    println!("Receiver COT data: {:?}", data);
}