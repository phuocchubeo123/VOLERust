use sha2::{Digest, Sha256};
use aes::Aes256;
use aes::cipher::{KeyInit, BlockEncrypt, generic_array::GenericArray};
use std::convert::TryInto;

/// Constants for the hash buffer and digest size
const HASH_BUFFER_SIZE: usize = 64;
const DIGEST_SIZE: usize = 32;

/// Represents a block as 128 bits (16 bytes)
pub type Block = [u8; 16];

/// Hash struct for managing incremental and static SHA-256 operations
pub struct Hash {
    hasher: Sha256,
    buffer: [u8; HASH_BUFFER_SIZE],
    size: usize,
}

impl Hash {
    /// Creates a new `Hash` instance
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            buffer: [0u8; HASH_BUFFER_SIZE],
            size: 0,
        }
    }

    /// Adds data to the hash input
    pub fn put(&mut self, data: &[u8]) {
        if data.len() >= HASH_BUFFER_SIZE {
            self.hasher.update(data);
        } else if self.size + data.len() < HASH_BUFFER_SIZE {
            self.buffer[self.size..self.size + data.len()].copy_from_slice(data);
            self.size += data.len();
        } else {
            self.hasher.update(&self.buffer[..self.size]);
            self.buffer[..data.len()].copy_from_slice(data);
            self.size = data.len();
        }
    }

    /// Adds one or more blocks to the hash input
    pub fn put_block(&mut self, blocks: &[Block]) {
        let byte_data = unsafe { std::slice::from_raw_parts(blocks.as_ptr() as *const u8, blocks.len() * 16) };
        self.put(byte_data);
    }

    /// Computes the final hash digest and writes it to the output
    pub fn digest(&mut self, output: &mut [u8; DIGEST_SIZE]) {
        if self.size > 0 {
            self.hasher.update(&self.buffer[..self.size]);
            self.size = 0;
        }
        let result = self.hasher.finalize_reset();
        output.copy_from_slice(&result[..DIGEST_SIZE]);
        self.reset();
    }

    /// Resets the hash state for reuse
    pub fn reset(&mut self) {
        self.hasher = Sha256::new();
        self.size = 0;
    }

    /// Computes a SHA-256 hash in one step
    pub fn hash_once(data: &[u8]) -> [u8; DIGEST_SIZE] {
        let mut hash = Self::new();
        let mut output = [0u8; DIGEST_SIZE];
        hash.put(data);
        hash.digest(&mut output);
        output
    }

    /// Computes a 128-bit block (first 16 bytes of the SHA-256 digest)
    pub fn hash_for_block(data: &[u8]) -> Block {
        let digest = Self::hash_once(data);
        let mut block = [0u8; 16];
        block.copy_from_slice(&digest[..16]);
        block
    }

    /// Key Derivation Function (KDF)
    pub fn kdf(point: &[u8], id: u64) -> Block {
        let mut combined = Vec::with_capacity(point.len() + 8);
        combined.extend_from_slice(point);            // Add point data
        combined.extend_from_slice(&id.to_le_bytes()); // Append `id` as little-endian bytes

        Self::hash_for_block(&combined)
    }
}

pub struct CCRH {
    aes_key: Aes256,
}

impl CCRH {
    /// Create a new CCRH instance with a given key
    pub fn new(key: &[u8; 32]) -> Self {
        let aes_key = Aes256::new(GenericArray::from_slice(key));
        CCRH { aes_key }
    }

    /// Permute blocks using AES encryption
    pub fn permute_block(&self, blocks: &mut [[u8; 16]]) {
        let mut generic_blocks: Vec<GenericArray<u8, _>> = blocks
            .iter()
            .map(|block| GenericArray::clone_from_slice(block))
            .collect();

        self.aes_key.encrypt_blocks(&mut generic_blocks);

        for (i, generic_block) in generic_blocks.iter().enumerate() {
            blocks[i].copy_from_slice(generic_block.as_slice());
        }
    }

    /// Single hash function
    pub fn h(&self, input: &[u8; 16]) -> [u8; 16] {
        let t = CCRH::sigma(input);

        let mut blocks = vec![t];
        self.permute_block(&mut blocks);

        CCRH::xor_block(&t, &blocks[0])
    }

    /// Hash multiple blocks
    pub fn hn(&self, output: &mut [[u8; 16]], input: &[[u8; 16]]) {
        let len = input.len();
        let mut tmp: Vec<[u8; 16]> = vec![[0; 16]; len];

        for (i, block) in input.iter().enumerate() {
            tmp[i] = block.clone();
            tmp[i].reverse(); // Simulates sigma by reversing the bytes
            output[i] = tmp[i];
        }

        self.permute_block(&mut tmp);

        for i in 0..len {
            output[i] = CCRH::xor_block(&output[i], &tmp[i]);
        }
    }

    /// A helper function to simulate sigma operation
    fn sigma(input: &[u8; 16]) -> [u8; 16] {
        let mut output = [0u8; 16];

        // Shuffle bytes: equivalent to _mm_shuffle_epi32(a, 78)
        // Here, 78 implies swapping certain groups of bytes. We achieve it manually.
        output[0..4].copy_from_slice(&input[4..8]);
        output[4..8].copy_from_slice(&input[0..4]);
        output[8..12].copy_from_slice(&input[12..16]);
        output[12..16].copy_from_slice(&input[8..12]);

        // Apply a mask and XOR: (a & mask) ^ shuffled
        let mask: [u8; 16] = [0xFF; 8].iter().chain(&[0x00; 8]).copied().collect::<Vec<u8>>().try_into().unwrap();
        for i in 0..16 {
            output[i] ^= input[i] & mask[i];
        }

        output
    }

    /// XOR two 16-byte arrays with unrolled loops
    pub(crate) fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        [
            a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3],
            a[4] ^ b[4], a[5] ^ b[5], a[6] ^ b[6], a[7] ^ b[7],
            a[8] ^ b[8], a[9] ^ b[9], a[10] ^ b[10], a[11] ^ b[11],
            a[12] ^ b[12], a[13] ^ b[13], a[14] ^ b[14], a[15] ^ b[15],
        ]
    }
}