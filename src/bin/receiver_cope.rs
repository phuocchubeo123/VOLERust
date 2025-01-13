use vole_rust::Cope;
use vole_rust::{F, FE};

fn main() {
    // Receiver setup
    let mut cope_receiver = Cope::new(1, 128);
    cope_receiver.initialize_receiver();

    // Example input value for u
    let u = FE::from(67890);

    // Perform receiver extend
    let receiver_result = cope_receiver.extend_receiver(u);

    // Print results
    println!("Receiver Result:");
    for (i, value) in receiver_result.iter().enumerate() {
        println!("Index {}: {}", i, value);
    }
}
