extern crate vole_rust;

use vole_rust::iknp::IKNP;
use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use std::net::TcpStream;

fn main() {
    // Establish connection to the receiver
    let stream = TcpStream::connect("127.0.0.1:12345").expect("Failed to connect to receiver");
    let mut io = TcpChannel::new(stream);

    let mut sender_iknp = IKNP::new(true);
    sender_iknp.setup_send(&mut io, None, None);

    let length = 2048;
    let mut data = vec![[0u8; 32]; length];
    sender_iknp.send_cot(&mut io, &mut data, length);

    println!("Sender COT data: {:?}", &data[..5]);
}
