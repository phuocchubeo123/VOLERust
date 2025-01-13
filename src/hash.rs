use sha2::{Digest, Sha256};

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
