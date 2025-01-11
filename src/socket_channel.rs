use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use std::io::{Read, Write};
use std::net::TcpStream;
use crate::comm_channel::CommunicationChannel;

pub struct SocketChannel {
    stream: TcpStream,
}

impl SocketChannel {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

impl CommunicationChannel for SocketChannel {
    fn send_scalar(&mut self, scalar: &FieldElement<Stark252PrimeField>) {
        let bytes = scalar.to_bytes_le();
        let size = bytes.len() as u64;
        self.stream
            .write_all(&size.to_le_bytes())
            .expect("Failed to send scalar size");
        self.stream.write_all(&bytes).expect("Failed to send scalar");
    }

    fn receive_scalar(&mut self) -> FieldElement<Stark252PrimeField> {
        let mut size_buf = [0u8; 8];
        self.stream
            .read_exact(&mut size_buf)
            .expect("Failed to receive scalar size");
        let size = u64::from_le_bytes(size_buf) as usize;

        let mut scalar_bytes = vec![0u8; size];
        self.stream
            .read_exact(&mut scalar_bytes)
            .expect("Failed to receive scalar bytes");

        FieldElement::<Stark252PrimeField>::from_bytes_le(&scalar_bytes)
            .expect("Failed to deserialize scalar")
    }

    fn send_data(&mut self, data: &[(u8, u8)]) {
        let size = data.len() as u64;
        self.stream
            .write_all(&size.to_le_bytes())
            .expect("Failed to send data size");

        for &(d0, d1) in data {
            self.stream
                .write_all(&[d0, d1])
                .expect("Failed to send data bytes");
        }
    }

    fn receive_data(&mut self) -> Vec<(u8, u8)> {
        let mut size_buf = [0u8; 8];
        self.stream
            .read_exact(&mut size_buf)
            .expect("Failed to receive data size");
        let size = u64::from_le_bytes(size_buf) as usize;

        let mut data = Vec::with_capacity(size);
        let mut buf = [0u8; 2];
        for _ in 0..size {
            self.stream
                .read_exact(&mut buf)
                .expect("Failed to receive data bytes");
            data.push((buf[0], buf[1]));
        }
        data
    }
}
