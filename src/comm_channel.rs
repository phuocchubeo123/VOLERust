use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;

pub trait CommunicationChannel {
    fn send_scalar(&mut self, scalar: &FieldElement<Stark252PrimeField>);
    fn receive_scalar(&mut self) -> FieldElement<Stark252PrimeField>;
    fn send_data(&mut self, data: &[(u8, u8)]);
    fn receive_data(&mut self) -> Vec<(u8, u8)>;
}
