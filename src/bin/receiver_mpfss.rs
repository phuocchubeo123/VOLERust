extern crate vole_rust;
extern crate lambdaworks_math;
extern crate rand;

use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use vole_rust::spfss_sender::SpfssSenderFp;
use vole_rust::preot::OTPre;
use vole_rust::base_cot::BaseCot;
use vole_rust::mpfss_reg::MpfssReg;
use vole_rust::base_svole::BaseSvole;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use std::net::TcpListener;
use rand::random;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub fn rand_field_element() -> FE {
    let rand_big = UnsignedInteger { limbs: random() };
    FE::new(rand_big)
}

fn main() {
    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    const log_bin_sz: usize = 5;
    const t: usize = 3;
    const n: usize = t * (1 << log_bin_sz);
    const k: usize = 2;

    // Initialize BaseCot for the sender (ALICE)
    let mut receiver_cot = BaseCot::new(1, false);

    // Set up the sender's precomputation phase
    receiver_cot.cot_gen_pre(&mut channel, None);
    let mut pre_ot = OTPre::new(log_bin_sz, t);
    receiver_cot.cot_gen_preot(&mut channel, &mut pre_ot, log_bin_sz*t, None);

    let mut mac = vec![FE::zero(); t+1];
    let mut u = vec![FE::zero(); t+1];

    // Base sVOLE first
    let mut svole = BaseSvole::new_receiver(&mut channel);
    // mac = key + delta * u
    svole.triple_gen_recv(&mut channel, &mut mac, &mut u, t+1);

    let mut y = vec![FE::zero(); n];
    let mut mpfss = MpfssReg::new::<n, t, log_bin_sz>(1);
    mpfss.set_malicious();

    mpfss.receiver_init();
    mpfss.mpfss_receiver(&mut channel, &mut pre_ot, &mac, &u, &mut y);
}