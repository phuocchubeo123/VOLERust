use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use rand::Rng;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct PRP {
    key: [u8; 16],
    aes: Aes128,
}

impl PRP {
    pub fn new(key: Option<&[u8; 16]>) -> Self {
        let mut aes_key = [0u8; 16];
        if let Some(k) = key {
            aes_key.copy_from_slice(k);
        } else {
            let mut rng = rand::thread_rng();
            rng.fill(&mut aes_key);
        }

        let aes = Aes128::new(GenericArray::from_slice(&aes_key));

        PRP {
            key: aes_key,
            aes: aes,
        }
    }

    pub fn permute_block(&self, data: &mut [[u8; 16]], nblocks: usize) {
        let mut aes_block: Vec<_> = data
            .iter()
            .map(|x| GenericArray::clone_from_slice(x))
            .collect();
        self.aes.encrypt_blocks(&mut aes_block);
        for (i, encrypted) in aes_block.iter().enumerate() {
            data[i].copy_from_slice(encrypted);
        }
    }
}


const NUM_ROUNDS: usize = 4;

// 4 rounds Luby-Rackoff construction
pub struct LubyRackoffPRP {
    keys: Vec<[u8; 16]>,
}

impl LubyRackoffPRP {
    pub fn new(seeds: Option<&[[u8; 16]]>) -> Self {
        let mut keys = vec![[0u8; 16]; NUM_ROUNDS];
        if let Some(s) = seeds {
            keys.copy_from_slice(s);
        } else {
            let mut rng = rand::thread_rng();
            for key in keys.iter_mut() {
                rng.fill(key);
            }
        }

        LubyRackoffPRP {
            keys: keys,
        }
    }

    pub fn permute_block(&self, data: &mut [FE], nblocks: usize) {
        let data_bytes: Vec<[u8; 32]> = data
            .iter()
            .map(|x| x.to_bytes_le())
            .collect();
        let mut data_left: Vec<[u8; 16]> = data_bytes
            .iter()
            .map(|x| {
                let mut block = [0u8; 16];
                block.copy_from_slice(&x[0..16]);
                block
            })
            .collect();
        let mut data_right : Vec<[u8; 16]> = data_bytes
            .iter()
            .map(|x| {
                let mut block = [0u8; 16];
                block.copy_from_slice(&x[16..32]);
                block
            })
            .collect();
        
        for i in 0..NUM_ROUNDS {
            let mut aes_block: Vec<_> = data_left
                .iter()
                .map(|x| GenericArray::clone_from_slice(x))
                .collect();
            let aes = Aes128::new(GenericArray::from_slice(&self.keys[i]));
            aes.encrypt_blocks(&mut aes_block);

            data_left.copy_from_slice(&data_right);
            data_right = aes_block
                .iter()
                .map(|x| {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(&x);
                    block
                })
                .collect();
            // xoring data_right (encrypted data_left) with data_left (former data_right)
            xor_block_array(&mut data_right, &data_left);
        }

        for (i, element) in data.iter_mut().enumerate() {
            let mut block = [0u8; 32];
            block[0..16].copy_from_slice(&data_left[i]);
            block[16..32].copy_from_slice(&data_right[i]);
            *element = FE::from_bytes_le(&block).expect("cannot transform prp-ed block into FE");
        }
    }
}

pub fn xor_block_array(a: &mut [[u8; 16]], b: &[[u8; 16]]) {
    for (block, other_block) in a.iter_mut().zip(b.iter()) {
        // Unroll the loop manually for 16 bytes
        block[0] ^= other_block[0];
        block[1] ^= other_block[1];
        block[2] ^= other_block[2];
        block[3] ^= other_block[3];
        block[4] ^= other_block[4];
        block[5] ^= other_block[5];
        block[6] ^= other_block[6];
        block[7] ^= other_block[7];
        block[8] ^= other_block[8];
        block[9] ^= other_block[9];
        block[10] ^= other_block[10];
        block[11] ^= other_block[11];
        block[12] ^= other_block[12];
        block[13] ^= other_block[13];
        block[14] ^= other_block[14];
        block[15] ^= other_block[15];
    }
}