use p256::EncodedPoint;

use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub trait CommunicationChannel {
    fn send_stark252(&mut self, elements: &[FE]) -> std::io::Result<()>;
    fn receive_stark252(&mut self, count: usize) -> std::io::Result<Vec<FE>>;
    fn send_point(&mut self, point: &EncodedPoint);
    fn receive_point(&mut self) -> EncodedPoint;
    fn send_data(&mut self, data: &[[u8; 16]]);
    fn receive_data(&mut self) -> Vec<[u8; 16]>;
    fn flush(&mut self);
}