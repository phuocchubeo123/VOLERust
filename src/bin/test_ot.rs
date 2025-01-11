use std::net::{TcpListener, TcpStream};
use std::thread;
use crate::socket_channel::SocketChannel;
use crate::ot::OTCO;

fn sender_thread(stream: TcpStream) {
    let mut channel = SocketChannel::new(stream);
    let ot = OTCO::new();

    let data0 = vec![1u8, 2u8, 3u8];
    let data1 = vec![4u8, 5u8, 6u8];

    ot.send(&mut channel, &data0, &data1);
}

fn receiver_thread(stream: TcpStream) {
    let mut channel = SocketChannel::new(stream);
    let ot = OTCO::new();

    let choices = vec![false, true, false];
    let mut output = Vec::new();

    ot.recv(&mut channel, &choices, &mut output);

    println!("Receiver output: {:?}", output);
}

fn main() {
    // Start a TCP listener for the sender
    let listener = TcpListener::bind("127.0.0.1:12345").expect("Failed to bind listener");

    // Spawn the sender thread
    thread::spawn(|| {
        let stream = TcpStream::connect("127.0.0.1:12345").expect("Failed to connect to sender");
        sender_thread(stream);
    });

    // Accept the sender's connection and start the receiver thread
    if let Ok((stream, _)) = listener.accept() {
        receiver_thread(stream);
    }
}
