extern crate p256;
extern crate vole_rust;

use std::net::{TcpListener, TcpStream};
use std::thread;

use p256::{AffinePoint, ProjectivePoint, PublicKey, Scalar};
use p256::elliptic_curve::sec1::EncodedPoint;

use vole_rust::ot::OTCO;
use vole_rust::hash::Hash;
use vole_rust::socket_channel::TcpChannel;

fn main() {
    // Start server and client in separate threads
    let server = thread::spawn(|| {
        let listener = TcpListener::bind("127.0.0.1:12345").expect("Failed to bind server");
        println!("Server listening on 127.0.0.1:12345");

        for stream in listener.incoming() {
            let stream = stream.expect("Failed to accept connection");
            let mut channel = TcpChannel::new(stream);

            // Sender data
            let data0 = vec![[0u8; 16]; 2]; // Example data0
            let data1 = vec![[1u8; 16]; 2]; // Example data1

            // Sender OT implementation
            let mut otco = OTCO::new(channel);
            otco.send(&data0, &data1);

            println!("Sender finished sending data");
        }
    });

    let client = thread::spawn(|| {
        let stream = TcpStream::connect("127.0.0.1:12345").expect("Failed to connect to server");
        let mut channel = TcpChannel::new(stream);

        // Receiver choices
        let choices = vec![false, true];
        let mut output = Vec::new();

        // Receiver OT implementation
        let mut otco = OTCO::new(channel);
        otco.recv(&choices, &mut output);

        // Check output correctness
        assert_eq!(output, vec![[0u8; 16], [1u8; 16]]);
        println!("Receiver received correct data");
    });

    server.join().unwrap();
    client.join().unwrap();
}
