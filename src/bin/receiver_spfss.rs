extern crate your_crate_name; // Replace with your actual crate name
use your_crate_name::spfss_recver_fp::SpfssRecverFp;
use your_crate_name::comm_channel::TcpChannel; // Replace with your communication channel module
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    let depth = 5; // Depth of the GGM tree
    let leave_n = 1 << (depth - 1);

    // Listen for the sender
    let listener = std::net::TcpListener::bind("127.0.0.1:8080")
        .expect("Failed to bind to address");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Initialize the receiver
    let mut receiver = SpfssRecverFp::new(&mut channel, depth);

    // Simulated OT
    let mut ot_recv = |msg: &mut [[u8; 16]], choices: &mut [bool], _s: usize| {
        let msg_0: Vec<u8> = channel.receive_data().expect("Failed to receive OT msg_0");
        let msg_1: Vec<u8> = channel.receive_data().expect("Failed to receive OT msg_1");

        for i in 0..msg.len() {
            msg[i] = if choices[i] {
                msg_1[i * 16..(i + 1) * 16].try_into().unwrap()
            } else {
                msg_0[i * 16..(i + 1) * 16].try_into().unwrap()
            };
        }
    };

    // Receive OT messages and reconstruct the tree
    receiver.recv(&mut ot_recv, depth - 1);

    // Compute the GGM tree
    let delta2 = FE::from(21u64); // Example delta2
    let mut ggm_tree_mem = vec![FE::zero(); leave_n];
    receiver.compute(&mut ggm_tree_mem, delta2.clone());

    // Perform the consistency check
    let z = FE::from(30u64); // Example value for z
    receiver.consistency_check(&mut channel, z.clone(), delta2.clone());

    println!("Receiver completed successfully!");
}
