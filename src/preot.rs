use crate::hash::CCRH;
use crate::comm_channel::CommunicationChannel;
use crate::socket_channel::TcpChannel;

// This is SO suspicious. Need to review in the future.

pub struct OTPre<'a, IO: CommunicationChannel> {
    io: &'a mut IO,
    pre_data: Vec<[u8; 16]>,
    bits: Vec<bool>,
    n: usize,
    count: usize,
    length: usize,
    ccrh: CCRH,
    delta: Option<[u8; 16]>,
}

impl<'a, IO: CommunicationChannel> OTPre<'a, IO> {
    /// Create a new `OTPre` instance
    pub fn new(io: &'a mut IO, length: usize, times: usize) -> Self {
        let n = length * times;
        Self {
            io,
            pre_data: vec![[0u8; 16]; 2 * n],
            bits: vec![false; n],
            n,
            count: 0,
            length,
            ccrh: CCRH::new(&[0u8; 32]),
            delta: None,
        }
    }

    /// Receives choice bits from the receiver and updates internal state
    pub fn choices_sender(&mut self) {
        // Receive choice bits from the receiver
        let received_bits = self.io.receive_bits().expect("Failed to receive bits");
        for (i, &bit) in received_bits.iter().enumerate() {
            self.bits[self.count + i] = bit;
        }
        self.count += self.length;
    }

    /// Sends the adjusted choice bits to the sender
    pub fn choices_recver(&mut self, choices: &[bool]) {
        let mut adjusted_bits = vec![false; self.length];
        for i in 0..self.length {
            adjusted_bits[i] = choices[i] ^ self.bits[self.count + i];
        }
        // Send adjusted choice bits to the sender
        self.io.send_bits(&adjusted_bits).expect("Failed to send bits");
        self.count += self.length;
    }

    /// Precompute data for the sender
    pub fn send_pre(&mut self, data: &[[u8; 16]], delta: [u8; 16]) {
        self.delta = Some(delta);

        let n = self.n;
        self.ccrh.hn(&mut self.pre_data[..n], data);

        for i in 0..n {
            self.pre_data[n + i] = CCRH::xor_block(&data[i], &delta);
        }

        let temp = self.pre_data[n..2 * n].to_vec(); // Copy to avoid overlapping borrows
        self.ccrh.hn(&mut self.pre_data[n..2 * n], &temp);
    }

    /// Precompute data for the receiver
    pub fn recv_pre(&mut self, data: &[[u8; 16]], bits: Option<&[bool]>) {
        if let Some(b) = bits {
            self.bits[..self.n].copy_from_slice(b);
        } else {
            for i in 0..self.n {
                self.bits[i] = data[i][0] & 1 != 0; // Extract LSB
            }
        }
        self.ccrh.hn(&mut self.pre_data[..self.n], data);
    }

    /// Send data based on precomputed values
    pub fn send(&mut self, m0: &[[u8; 16]], m1: &[[u8; 16]], length: usize, s: usize) {
        let mut pad = [[0u8; 16]; 2];
        let k = s * length;

        for i in 0..length {
            let idx = k + i;
            if !self.bits[idx] {
                pad[0] = CCRH::xor_block(&m0[i], &self.pre_data[idx]);
                pad[1] = CCRH::xor_block(&m1[i], &self.pre_data[idx + self.n]);
            } else {
                pad[0] = CCRH::xor_block(&m0[i], &self.pre_data[idx + self.n]);
                pad[1] = CCRH::xor_block(&m1[i], &self.pre_data[idx]);
            }
            self.io.send_data(&pad);
        }
    }

    /// Receive and reconstruct data based on precomputed values
    pub fn recv(&mut self, data: &mut [[u8; 16]], b: &[bool], length: usize, s: usize) {
        let mut pad = [[0u8; 16]; 2];
        let k = s * length;

        for i in 0..length {
            let received = self.io.receive_data();
            pad.copy_from_slice(&received);

            let idx = if b[i] { 1 } else { 0 };
            data[i] = CCRH::xor_block(&self.pre_data[k + i], &pad[idx]);
        }
    }

    /// Reset the internal counter
    pub fn reset(&mut self) {
        self.count = 0;
    }
}
