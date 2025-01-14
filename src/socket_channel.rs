use crate::comm_channel::CommunicationChannel;

use std::net::TcpStream;
use p256::EncodedPoint;

use std::io::{Write, Read};

use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

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
    /// Sends a vector of STARK-252 field elements over the TCP channel.
    fn send_stark252(&mut self, elements: &[FE]) -> std::io::Result<()> {
        // Serialize each field element into 32-byte little-endian representation
        let mut serialized_data = Vec::new();
        for element in elements {
            serialized_data.extend_from_slice(&element.to_bytes_le());
        }

        // Calculate the total size of the serialized data
        let total_size = serialized_data.len() as u64;

        // Send the size prefix
        self.stream.write_all(&total_size.to_le_bytes())?;

        // Send the serialized data
        self.stream.write_all(&serialized_data)?;

        Ok(())
    }

    /// Receives a vector of STARK-252 field elements from the TCP channel.
    fn receive_stark252(&mut self, count: usize) -> std::io::Result<Vec<FE>> {
        // Read the size prefix
        let mut size_buf = [0u8; 8];
        self.stream.read_exact(&mut size_buf)?;
        let received_size = u64::from_le_bytes(size_buf);

        // Validate the size
        let expected_size = (count * 32) as u64;
        if received_size != expected_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Unexpected data size received: expected {}, got {}",
                    expected_size, received_size
                ),
            ));
        }

        // Receive the serialized data
        let mut raw_data = vec![0u8; received_size as usize];
        self.stream.read_exact(&mut raw_data)?;

        // Deserialize the field elements from the serialized data
        let elements = raw_data
            .chunks_exact(32)
            .map(|chunk| {
                FE::from_bytes_le(chunk).expect("Failed to deserialize STARK-252 element")
            })
            .collect();

        Ok(elements)
    }

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
