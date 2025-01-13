extern crate vole_rust;

use vole_rust::ot::OTCO;
use vole_rust::socket_channel::TcpChannel;
use std::net::TcpStream;

fn main() {
    // Connect to the sender
    let stream = TcpStream::connect("127.0.0.1:12345").expect("Failed to connect to sender");
    let mut channel = TcpChannel::new(stream);

    // Example choices
    let choices = vec![false, true];
    let mut output = Vec::new();

    // Initialize OTCO and receive
    let mut otco = OTCO::new(channel);
    otco.recv(&choices, &mut output);

    // Verify the output
    println!("Received output: {:?}", output);
}
