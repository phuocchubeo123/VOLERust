extern crate your_crate_name; // Replace with your actual crate name
use your_crate_name::spfss_sender_fp::SpfssSenderFp;
use your_crate_name::comm_channel::TcpChannel; // Replace with your communication channel module
use your_crate_name::prg::PRG;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    let depth = 5; // Depth of the GGM tree
    let leave_n = 1 << (depth - 1);

    // Connect to the receiver
    let stream = std::net::TcpStream::connect("127.0.0.1:8080")
        .expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Initialize the sender
    let mut sender = SpfssSenderFp::new(&mut channel, depth);

    // Simulated secret and gamma
    let secret = FE::from(42u64); // Example secret
    let gamma = FE::from(17u64);  // Example gamma

    // Compute the GGM tree
    let mut ggm_tree_mem = vec![FE::zero(); leave_n];
    sender.compute(&mut ggm_tree_mem, secret.clone(), gamma.clone());

    // Simulated OT
    let mut ot_send = |msg_0: &[[u8; 16]], msg_1: &[[u8; 16]], _s: usize| {
        channel.send_data(&msg_0.concat()).expect("Failed to send OT msg_0");
        channel.send_data(&msg_1.concat()).expect("Failed to send OT msg_1");
    };

    // Send OT messages and secret sum
    sender.send(&mut ot_send, depth - 1);

    // Perform the consistency check
    let y = FE::from(30u64); // Example value for y
    sender.consistency_check(&mut channel, y.clone());

    println!("Sender completed successfully!");
}
