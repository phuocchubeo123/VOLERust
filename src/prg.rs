use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;
use rand::Rng;

/// Alias for the STARK-252 prime field and its field element.
pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct PRG {
    counter: u64,
    aes: Aes128,
    key: [u8; 16],
}

impl PRG {
    /// Create a new PRG instance with an optional seed and ID.
    pub fn new(seed: Option<&[u8; 16]>, id: u64) -> Self {
        let mut key = [0u8; 16];
        if let Some(s) = seed {
            key.copy_from_slice(s);
        } else {
            key = PRG::generate_random_key();
        }
        PRG::apply_id_to_key(&mut key, id);

        let aes = Aes128::new(GenericArray::from_slice(&key));
        PRG {
            counter: 0,
            aes,
            key,
        }
    }

    /// Generate a random 16-byte key using a secure random generator.
    fn generate_random_key() -> [u8; 16] {
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 16];
        rng.fill(&mut key);
        key
    }

    /// Apply the ID to the key for reseeding purposes.
    fn apply_id_to_key(key: &mut [u8; 16], id: u64) {
        let id_bytes = id.to_le_bytes();
        for (i, byte) in id_bytes.iter().enumerate() {
            key[i] ^= byte;
        }
    }

    /// Reseed the PRG with a new seed and ID.
    pub fn reseed(&mut self, seed: &[u8; 16], id: u64) {
        self.key.copy_from_slice(seed);
        PRG::apply_id_to_key(&mut self.key, id);
        self.aes = Aes128::new(GenericArray::from_slice(&self.key));
        self.counter = 0;
    }

    /// Generate `blocks.len()` random 16-byte blocks in-place.
    pub fn random_block(&mut self, blocks: &mut [[u8; 16]]) {
        for block in blocks.iter_mut() {
            block[8..].copy_from_slice(&self.counter.to_le_bytes());
            let mut aes_block = GenericArray::clone_from_slice(block);
            self.aes.encrypt_block(&mut aes_block);
            *block = aes_block.into();
            self.counter += 1;
        }
    }

    /// Generate `elements.len()` random STARK-252 field elements in-place.
    pub fn random_stark252_elements(&mut self, elements: &mut [FE]) {
        for element in elements.iter_mut() {
            let mut block1 = [0u8; 16];
            let mut block2 = [0u8; 16];

            // Generate the first 16 bytes
            block1[8..].copy_from_slice(&self.counter.to_le_bytes());
            let mut aes_block1 = GenericArray::clone_from_slice(&block1);
            self.aes.encrypt_block(&mut aes_block1);
            block1 = aes_block1.into();
            self.counter += 1;

            // Generate the second 16 bytes
            block2[8..].copy_from_slice(&self.counter.to_le_bytes());
            let mut aes_block2 = GenericArray::clone_from_slice(&block2);
            self.aes.encrypt_block(&mut aes_block2);
            block2 = aes_block2.into();
            self.counter += 1;

            // Combine the two 16-byte blocks into a 32-byte array
            let mut value_bytes = [0u8; 32];
            value_bytes[..16].copy_from_slice(&block1);
            value_bytes[16..].copy_from_slice(&block2);

            // Convert to STARK-252 field element
            *element = FE::from_bytes_le(&value_bytes).unwrap();
        }
    }

}
