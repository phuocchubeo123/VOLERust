extern crate vole_rust;

use vole_rust::ot::OTCO;
use vole_rust::socket_channel::TcpChannel;
use std::net::TcpListener;

fn main() {
    // Start the sender
    let listener = TcpListener::bind("127.0.0.1:12345").expect("Failed to bind server");
    println!("Sender is listening on 127.0.0.1:12345");

    for stream in listener.incoming() {
        let stream = stream.expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        // Example data
        let data0 = vec![[0u8; 16]; 2];
        let data1 = vec![[1u8; 16]; 2];

        // Initialize OTCO and send
        let mut otco = OTCO::new(channel);
        otco.send(&data0, &data1);

        println!("Sender finished sending data");
    }
}