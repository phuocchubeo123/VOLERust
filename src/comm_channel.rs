use p256::EncodedPoint;
use std::io::{Read, Write};

pub trait CommunicationChannel {
    pub fn send_stark252(&mut self, elements: &[FE]) -> std::io::Result<()>;
    pub fn receive_stark252(&mut self, count: usize) -> std::io::Result<Vec<FE>>;
    fn send_point(&mut self, point: &EncodedPoint);
    fn receive_point(&mut self) -> EncodedPoint;
    fn send_data(&mut self, data: &[[u8; 16]]);
    fn receive_data(&mut self) -> Vec<[u8; 16]>;
    fn flush(&mut self);
}