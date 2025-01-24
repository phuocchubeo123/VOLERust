
extern crate vole_rust;
extern crate lambdaworks_math;
extern crate rand;

use vole_rust::comm_channel::CommunicationChannel;
use vole_rust::socket_channel::TcpChannel;
use vole_rust::spfss_sender::SpfssSenderFp;
use vole_rust::preot::OTPre;
use vole_rust::base_cot::BaseCot;
use vole_rust::mpfss_reg::MpfssReg;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use std::net::TcpStream;
use rand::random;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub fn rand_field_element() -> FE {
    let rand_big = UnsignedInteger { limbs: random() };
    FE::new(rand_big)
}

fn main() {
    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Initialize BaseCot for the sender (ALICE)
    let mut sender_cot = BaseCot::new(0, false);

    // Set up the sender's precomputation phase
    sender_cot.cot_gen_pre(None);

    const log_bin_sz = 5;
    const t = 3;
    const n = t * (1 << log_bin_sz);

    let mut mpfss = MpfssReg::new::<n, t, log_bin_sz>(0);
    mpfss.set_malicious();

    let pre_ot = OTPre::new(log_bin_sz, t);

    let delta = rand_field_element();

    mpfss.sender_init(delta);
    // TODO
}