use crate::comm_channel::CommunicationChannel;

use std::net::TcpStream;
use p256::EncodedPoint;
use p256::{AffinePoint, ProjectivePoint, PublicKey, Scalar};

use std::io::{Write, Read};

pub struct TcpChannel {
    stream: TcpStream,
}

impl TcpChannel {
    /// Creates a new TcpChannel
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

impl CommunicationChannel for TcpChannel {
    fn send_point(&mut self, point: &EncodedPoint) {
        let point_bytes = point.as_bytes(); // Serialize the point
        let size = point_bytes.len() as u64;

        // Send the size and then the serialized point data
        self.stream
            .write_all(&size.to_le_bytes())
            .expect("Failed to send point size");
        self.stream
            .write_all(point_bytes)
            .expect("Failed to send point");
    }

    fn receive_point(&mut self) -> EncodedPoint {
        // Read the size of the incoming point
        let mut size_buf = [0u8; 8];
        self.stream
            .read_exact(&mut size_buf)
            .expect("Failed to receive point size");
        let size = u64::from_le_bytes(size_buf) as usize;

        // Read the serialized point data
        let mut point_bytes = vec![0u8; size];
        self.stream
            .read_exact(&mut point_bytes)
            .expect("Failed to receive point data");

        // Deserialize the point
        EncodedPoint::from_bytes(&point_bytes).expect("Invalid point received")
    }

    fn send_data(&mut self, data: &[[u8; 16]]) {
        let size = data.len() as u64;

        // Send the size of the data array
        self.stream.write_all(&size.to_le_bytes()).expect("Failed to send data size");

        // Send the 128-bit blocks
        for block in data {
            self.stream.write_all(block).expect("Failed to send data block");
        }
    }

    fn receive_data(&mut self) -> Vec<[u8; 16]> {
        let mut size_buf = [0u8; 8];
        self.stream.read_exact(&mut size_buf).expect("Failed to receive data size");
        let size = u64::from_le_bytes(size_buf) as usize;

        let mut data = Vec::with_capacity(size);
        for _ in 0..size {
            let mut block = [0u8; 16];
            self.stream.read_exact(&mut block).expect("Failed to receive data block");
            data.push(block);
        }
        data
    }

    fn flush(&mut self) {
        self.stream.flush().expect("Failed to flush stream");
    }
}
