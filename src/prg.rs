use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce}; // AES-GCM for encryption
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

/// PRG struct implementing pseudorandom generation with AES-GCM.
pub struct PRG {
    key: Key<Aes128Gcm>, // AES-128 key
    counter: u64,        // Counter for generating unique nonces
}

impl PRG {
    /// Creates a new PRG instance with an optional seed.
    pub fn new(seed: Option<[u8; 16]>) -> Self {
        let key_bytes = match seed {
            Some(seed) => seed,
            None => {
                let mut rng = ChaChaRng::from_entropy();
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                key
            }
        };

        let key = Key::from_slice(&key_bytes);
        PRG {
            key: *key,
            counter: 0,
        }
    }

    /// Reseeds the PRG with a new seed and optionally resets the counter.
    pub fn reseed(&mut self, new_seed: [u8; 16], reset_counter: bool) {
        self.key = *Key::from_slice(&new_seed); // Update the AES-GCM key
        if reset_counter {
            self.counter = 0; // Reset the counter if requested
        }
    }

    /// Generates `nblocks` random blocks of 16 bytes each.
    pub fn random_block(&mut self, nblocks: usize) -> Vec<[u8; 16]> {
        let mut output = Vec::with_capacity(nblocks);
        let aes_gcm = Aes128Gcm::new(&self.key);

        for _ in 0..nblocks {
            let nonce_bytes = self.counter.to_le_bytes(); // Counter-based nonce
            self.counter += 1;

            let nonce = Nonce::from_slice(&nonce_bytes[0..12]); // AES-GCM nonce is 12 bytes
            let plaintext = [0u8; 16]; // Input block of zeros
            let ciphertext = aes_gcm
                .encrypt(nonce, plaintext.as_ref())
                .expect("Encryption failed");

            let mut block = [0u8; 16];
            block.copy_from_slice(&ciphertext[0..16]); // Take the first 16 bytes
            output.push(block);
        }

        output
    }

    /// Generates `nbytes` random bytes.
    pub fn random_data(&mut self, nbytes: usize) -> Vec<u8> {
        let nblocks = (nbytes + 15) / 16; // Ceiling division
        let mut data = vec![0u8; nbytes];

        let blocks = self.random_block(nblocks);
        for (i, block) in blocks.iter().enumerate() {
            let start = i * 16;
            let end = (start + 16).min(nbytes);
            data[start..end].copy_from_slice(&block[..end - start]);
        }

        data
    }
}
