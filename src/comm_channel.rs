use p256::EncodedPoint;
use std::io::{Read, Write};

pub trait CommunicationChannel {
    fn send_point(&mut self, point: &EncodedPoint);
    fn receive_point(&mut self) -> EncodedPoint;
    fn send_data(&mut self, data: &[[u8; 16]]);
    fn receive_data(&mut self) -> Vec<[u8; 16]>;
    fn flush(&mut self);
}