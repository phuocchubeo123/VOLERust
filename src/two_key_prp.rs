use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct TwoKeyPRP {
    aes_keys_0: [Aes128; 4], // AES keys for the first child
    aes_keys_1: [Aes128; 4], // AES keys for the second child
}

impl TwoKeyPRP {
    /// Create a new `TwoKeyPRP` instance with 8 AES-128 keys (4 for each child).
    pub fn new(keys_0: [&[u8; 16]; 4], keys_1: [&[u8; 16]; 4]) -> Self {
        let aes_keys_0 = keys_0.map(|key| Aes128::new(GenericArray::from_slice(key)));
        let aes_keys_1 = keys_1.map(|key| Aes128::new(GenericArray::from_slice(key)));
        Self {
            aes_keys_0,
            aes_keys_1,
        }
    }

    /// Feistel round function: AES encryption followed by XOR.
    fn feistel_round(
        &self,
        round_key: &Aes128,
        left: &mut [u8; 16],
        right: &mut [u8; 16],
    ) {
        let mut tmp = GenericArray::clone_from_slice(right);
        round_key.encrypt_block(&mut tmp);

        for i in 0..16 {
            right[i] = left[i] ^ tmp[i];
            left[i] = right[i];
        }
    }

    /// Perform 256-to-256 PRP using Feistel network with 4 rounds.
    fn encrypt_feistel(&self, input: &[u8; 32], aes_keys: &[Aes128; 4]) -> [u8; 32] {
        let (left, right) = input.split_at(16);
        let mut left_block = [0u8; 16];
        let mut right_block = [0u8; 16];
        left_block.copy_from_slice(left);
        right_block.copy_from_slice(right);

        for round in 0..4 {
            if round % 2 == 0 {
                self.feistel_round(&aes_keys[round], &mut left_block, &mut right_block);
            } else {
                self.feistel_round(&aes_keys[round], &mut right_block, &mut left_block);
            }
        }

        let mut result = [0u8; 32];
        result[..16].copy_from_slice(&left_block);
        result[16..].copy_from_slice(&right_block);
        result
    }

    /// Expand a single parent field element into two child field elements.
    pub fn node_expand_1to2(&self, children: &mut [FE; 2], parent: &FE) {
        let parent_bytes = parent.to_bytes_le();

        // Encrypt using two Feistel networks
        let encrypted_0 = self.encrypt_feistel(&parent_bytes, &self.aes_keys_0);
        let encrypted_1 = self.encrypt_feistel(&parent_bytes, &self.aes_keys_1);

        // Convert the encrypted results into field elements
        children[0] = FE::from_bytes_le(&encrypted_0).unwrap();
        children[1] = FE::from_bytes_le(&encrypted_1).unwrap();
    }

    /// Expand two parent field elements into four child field elements.
    pub fn node_expand_2to4(&self, children: &mut [FE; 4], parents: &[FE; 2]) {
        for (i, parent) in parents.iter().enumerate() {
            let mut temp_children = [FE::zero(); 2];
            self.node_expand_1to2(&mut temp_children, parent);
            children[i * 2] = temp_children[0].clone();
            children[i * 2 + 1] = temp_children[1].clone();
        }
    }

    /// Expand four parent field elements into eight child field elements.
    pub fn node_expand_4to8(&self, children: &mut [FE; 8], parents: &[FE; 4]) {
        for (i, parent) in parents.iter().enumerate() {
            let mut temp_children = [FE::zero(); 2];
            self.node_expand_1to2(&mut temp_children, parent);
            children[i * 2] = temp_children[0].clone();
            children[i * 2 + 1] = temp_children[1].clone();
        }
    }
}
