use crate::two_key_prp::TwoKeyPRP;
use crate::prg::PRG;
use crate::comm_channel::CommunicationChannel;
use crate::preot::OTPre;
use crate::hash::Hash;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;
use std::convert::TryInto;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct SpfssRecverFp {
    ggm_tree: Vec<FE>,
    m: Vec<FE>,
    pub(crate) b: Vec<bool>,
    choice_pos: usize,
    depth: usize,
    leave_n: usize,
    share: FE,
}

impl SpfssRecverFp {
    /// Create a new SpfssRecverFp instance.
    pub fn new(depth: usize) -> Self {
        let leave_n = 1 << (depth - 1);
        Self {
            ggm_tree: vec![FE::zero(); leave_n],
            m: vec![FE::zero(); depth - 1],
            b: vec![false; depth - 1],
            choice_pos: (1 << depth - 1) - 1,
            depth,
            leave_n,
            share: FE::zero(),
        }
    }

    pub fn get_index(&self) -> usize {
        let mut choice_pos = 0;
        for i in 0..self.depth-1 {
            choice_pos <<= 1;
            if !self.b[i] {
                choice_pos += 1;
            }
        }
        choice_pos
    }

    /// Receive the message and reconstruct the tree.
    pub fn recv<IO: CommunicationChannel>(&mut self, io: &mut IO, ot: &mut OTPre, s: usize) {
        let mut receive_data = vec![[0u8; 32]; self.depth - 1];
        ot.recv(io, &mut receive_data, &mut self.b, self.depth - 1, s);

        // println!("Messages received in PreOT: {:?}", receive_data);

        self.m = receive_data
            .iter()
            .map(|x| FE::from_bytes_le(x).unwrap())
            .collect::<Vec<FE>>();
        self.share = io.receive_stark252(1).expect("Failed to receive share")[0];
    }

    /// Compute the GGM tree and reconstruct the nodes.
    pub fn compute(&mut self, ggm_tree_mem: &mut [FE], delta2: FE) {
        self.reconstruct_tree();
        ggm_tree_mem.copy_from_slice(&self.ggm_tree);

        self.ggm_tree[self.choice_pos] = FE::zero();
        let mut nodes_sum = FE::zero();
        for i in 0..self.leave_n {
            nodes_sum += ggm_tree_mem[i];
        }
        nodes_sum += self.share;
        ggm_tree_mem[self.choice_pos] = delta2 - nodes_sum;
    }

    /// Reconstruct the GGM tree.
    fn reconstruct_tree(&mut self) {
        let mut to_fill_idx = 0;
        let mut prp = TwoKeyPRP::new();

        for i in 1..self.depth {
            to_fill_idx *= 2;
            self.ggm_tree[to_fill_idx] = FE::zero();
            self.ggm_tree[to_fill_idx + 1] = FE::zero();

            if !self.b[i - 1] {
                self.layer_recover(i, 0, to_fill_idx, self.m[i - 1], &mut prp);
                to_fill_idx += 1;
            } else {
                self.layer_recover(i, 1, to_fill_idx + 1, self.m[i - 1], &mut prp);
            }
        }
    }

    /// Recover a single layer of the GGM tree.
    fn layer_recover(
        &mut self,
        depth: usize,
        lr: usize,
        to_fill_idx: usize,
        sum: FE,
        prp: &mut TwoKeyPRP,
    ) {
        let item_n = 1 << depth;
        let mut nodes_sum = FE::zero();
        let mut lr_start = 0;
        if lr != 0 {
            lr_start = 1;
        }

        for i in (lr_start..item_n).step_by(2) {
            nodes_sum += self.ggm_tree[i];
        }

        self.ggm_tree[to_fill_idx] = sum - nodes_sum;

        if depth == self.depth - 1 {
            return;
        }

        let tmp = self.ggm_tree.clone();

        for i in (0..item_n).step_by(2).rev() {
            prp.node_expand_2to4(
                &mut self.ggm_tree[i * 2..i * 2 + 4],
                &tmp[i..i + 2],
            );
        }
    }

    /// Consistency check for the protocol.
    pub fn consistency_check<IO: CommunicationChannel>(&mut self, io: &mut IO, z: FE, beta: FE) {
        let hash = Hash::new();
        let digest = hash.hash_32byte_block(&self.share.to_bytes_le());
        let uni_hash_seed = FE::from_bytes_le(&digest).unwrap();
        let mut chi = vec![FE::zero(); self.leave_n];
        uni_hash_coeff_gen(&mut chi, uni_hash_seed, self.leave_n);

        // Compute x_star
        let x_star = chi[self.choice_pos] * beta - z;
        // Send x_star
        io.send_stark252(&[x_star]).unwrap();

        // Compute W
        let w = vector_inner_product(&chi, &self.ggm_tree) - z;

        // Receive V and verify
        let v = io.receive_stark252(1).expect("Failed to receive V")[0];

        if w != v {
            panic!("SPFSS consistency check failed!");
        } else {
            println!("SPFSS successful!");
        }
    }

    pub fn consistency_check_msg_gen<IO: CommunicationChannel>(&mut self, chi_alpha: &mut FE, w: &mut FE, io: &mut IO, beta: FE, seed: FE) {
        let mut chi = vec![FE::zero(); self.leave_n];

        let hash = Hash::new();
        let digest = hash.hash_32byte_block(&seed.to_bytes_le());
        let uni_hash_seed = FE::from_bytes_le(&digest).unwrap();

        uni_hash_coeff_gen(&mut chi, uni_hash_seed, self.leave_n);

        *chi_alpha = chi[self.choice_pos];
        *w = vector_inner_product(&chi, &self.ggm_tree);

        // No idea
        self.ggm_tree[self.choice_pos] += beta;
    }
}

/// Compute modular inner product.
fn vector_inner_product(vec1: &[FE], vec2: &[FE]) -> FE {
    vec1.iter()
        .zip(vec2)
        .fold(FE::zero(), |acc, (v1, v2)| acc + (*v1 * *v2))
}

pub fn uni_hash_coeff_gen(coeff: &mut [FE], seed: FE, sz: usize) {
    if sz == 0 {
        return;
    }

    // Handle small `sz`
    coeff[0] = seed.clone();
    if sz == 1 {
        return;
    }

    coeff[1] = &coeff[0] * &seed;
    if sz == 2 {
        return;
    }

    coeff[2] = &coeff[1] * &seed;
    if sz == 3 {
        return;
    }

    let multiplier = &coeff[2] * &seed;
    coeff[3] = multiplier.clone();
    if sz == 4 {
        return;
    }

    // Compute the rest in batches of 4
    let mut i = 4;
    while i + 3 < sz {
        coeff[i] = &coeff[i - 4] * &multiplier;
        coeff[i + 1] = &coeff[i - 3] * &multiplier;
        coeff[i + 2] = &coeff[i - 2] * &multiplier;
        coeff[i + 3] = &coeff[i - 1] * &multiplier;
        i += 4;
    }

    // Handle remaining elements
    let remainder = sz % 4;
    if remainder != 0 {
        let start = sz - remainder;
        for j in 0..remainder {
            coeff[start + j] = &coeff[start + j - 1] * &seed;
        }
    }
}
