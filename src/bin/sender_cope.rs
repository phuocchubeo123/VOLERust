use vole_rust::Cope;
use vole_rust::{F, FE};

fn main() {
    // Sender setup
    let mut cope_sender = Cope::new(0, 128);
    let delta = FE::from(12345); // Example delta value
    cope_sender.initialize_sender(delta);

    // Perform sender extend
    let sender_result = cope_sender.extend_sender();

    // Print results
    println!("Sender Result:");
    for (i, value) in sender_result.iter().enumerate() {
        println!("Index {}: {}", i, value);
    }
}
