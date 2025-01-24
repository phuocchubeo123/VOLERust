extern crate vole_rust;
extern crate rand;

use vole_rust::iknp::IKNP;
use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use std::net::TcpListener;
use rand::Rng;

fn main() {
    // Bind and wait for a connection from the sender
    let listener = TcpListener::bind("127.0.0.1:12345").expect("Failed to bind to address");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut io = TcpChannel::new(stream);

    let mut receiver_iknp = IKNP::new(true);
    receiver_iknp.setup_recv(&mut io, None, None);

    const length: usize = 2048;
    let mut data = vec![[0u8; 32]; length];
    let mut rng = rand::thread_rng();
    let r: [bool; length] = [(); length].map(|_| rng.gen_bool(0.5)); // Example choice bits

    receiver_iknp.recv_cot(&mut io, &mut data, &r, length);

    println!("Choice bits: {:?}", &r[..5]);
    println!("Receiver COT data: {:?}", &data[..5]);
}