extern crate vole_rust;

use vole_rust::socket_channel::TcpChannel;
use vole_rust::vole_triple::{FP_DEFAULT, VoleTriple, WOLVERINE_LPN};
use std::net::TcpListener;
use std::time::Instant;

fn main() {
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    let mut vole = VoleTriple::new(1, false, &mut channel, WOLVERINE_LPN);
    
    let start = Instant::now();
    vole.setup_receiver(&mut channel);
    println!("Time taken for setup: {:?}", start.elapsed());
}