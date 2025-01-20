extern crate vole_rust;

use vole_rust::preot::OTPre;
use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use std::net::TcpStream;

fn main() {
    let tcp_stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut io = TcpChannel::new(tcp_stream);

    let length = 10; // Number of messages
    let times = 1;   // Single round for simplicity

    let mut ot_sender = OTPre::new(&mut io, length, times);

    let m0: Vec<[u8; 16]> = vec![[0x01; 16]; length];
    let m1: Vec<[u8; 16]> = vec![[0x02; 16]; length];
    let delta = [0xFF; 16];

    // Precompute sender data
    let data: Vec<[u8; 16]> = vec![[0x03; 16]; length];
    ot_sender.send_pre(&data, delta);

    // Receive choice bits from the receiver
    ot_sender.choices_sender();

    // Send the data
    ot_sender.send(&m0, &m1, length, 0);
}