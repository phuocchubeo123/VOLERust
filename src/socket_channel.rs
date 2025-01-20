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
    /// Sends an array of bits over the TCP channel.
    fn send_bits(&mut self, bits: &[bool]) -> std::io::Result<()> {
        // Serialize bits into bytes
        let mut byte_array = Vec::with_capacity((bits.len() + 7) / 8);
        let mut current_byte = 0u8;
        for (i, &bit) in bits.iter().enumerate() {
            if bit {
                current_byte |= 1 << (i % 8);
            }
            if i % 8 == 7 || i == bits.len() - 1 {
                byte_array.push(current_byte);
                current_byte = 0;
            }
        }

        // Send the total number of bits (as u64) and the byte array
        let num_bits = bits.len() as u64;
        self.stream.write_all(&num_bits.to_le_bytes())?;
        self.stream.write_all(&byte_array)?;

        Ok(())
    }

    /// Receives an array of bits over the TCP channel.
    fn receive_bits(&mut self) -> std::io::Result<Vec<bool>> {
        // Read the total number of bits (u64)
        let mut num_bits_buf = [0u8; 8];
        self.stream.read_exact(&mut num_bits_buf)?;
        let num_bits = u64::from_le_bytes(num_bits_buf) as usize;

        // Read the serialized byte array
        let num_bytes = (num_bits + 7) / 8;
        let mut byte_array = vec![0u8; num_bytes];
        self.stream.read_exact(&mut byte_array)?;

        // Deserialize bytes back into bits
        let mut bits = Vec::with_capacity(num_bits);
        for (i, &byte) in byte_array.iter().enumerate() {
            for j in 0..8 {
                if i * 8 + j >= num_bits {
                    break;
                }
                bits.push((byte & (1 << j)) != 0);
            }
        }

        Ok(bits)
    }

    /// Sends a vector of STARK-252 field elements over the TCP channel.
    fn send_stark252(&mut self, elements: &[FE]) -> std::io::Result<()> {
        // Define the chunk size (in bytes). For example, 32 elements (32 bytes each) per chunk.
        const CHUNK_SIZE: usize = 1024; // Adjust this as needed

        // Serialize all elements into a vector
        let mut serialized_data = Vec::with_capacity(elements.len() * 32);
        for element in elements {
            serialized_data.extend_from_slice(&element.to_bytes_le());
        }

        // Calculate the total size of the data
        let total_size = serialized_data.len() as u64;

        // Send the total size
        self.stream.write_all(&total_size.to_le_bytes())?;

        // Send data in chunks
        let mut start = 0;
        while start < serialized_data.len() {
            let end = (start + CHUNK_SIZE).min(serialized_data.len());
            self.stream.write_all(&serialized_data[start..end])?;
            start = end;
        }

        Ok(())
    }

    fn receive_stark252(&mut self, count: usize) -> std::io::Result<Vec<FE>> {
        // Define the chunk size (in bytes)
        const CHUNK_SIZE: usize = 1024; // Adjust this as needed

        // Read the total size prefix
        let mut size_buf = [0u8; 8];
        self.stream.read_exact(&mut size_buf)?;
        let total_size = u64::from_le_bytes(size_buf);

        // Validate the size
        let expected_size = (count * 32) as u64;
        if total_size != expected_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Unexpected data size received: expected {}, got {}",
                    expected_size, total_size
                ),
            ));
        }

        // Receive data in chunks
        let mut raw_data = vec![0u8; total_size as usize];
        let mut received = 0;
        while received < total_size as usize {
            let end = (received + CHUNK_SIZE).min(total_size as usize);
            self.stream.read_exact(&mut raw_data[received..end])?;
            received = end;
        }

        // Deserialize the elements
        let elements: Result<Vec<_>, _> = raw_data
            .chunks_exact(32)
            .map(FE::from_bytes_le)
            .collect();

        elements.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to deserialize STARK-252 element: {:?}", e),
            )
        })
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
