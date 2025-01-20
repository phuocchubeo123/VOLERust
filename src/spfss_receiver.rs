use crate::two_key_prp::TwoKeyPRP;
use crate::prg::PRG;
use crate::comm_channel::CommunicationChannel;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct SpfssRecverFp<'a, IO> {
    io: &'a mut IO,
    ggm_tree: Vec<FE>,
    m: Vec<[u8; 16]>,
    b: Vec<bool>,
    choice_pos: usize,
    depth: usize,
    leave_n: usize,
    share: FE,
}

impl<'a, IO: CommunicationChannel> SpfssRecverFp<'a, IO> {
    /// Create a new SpfssRecverFp instance.
    pub fn new(io: &'a mut IO, depth: usize) -> Self {
        let leave_n = 1 << (depth - 1);
        Self {
            io,
            ggm_tree: vec![FE::zero(); leave_n],
            m: vec![[0u8; 16]; depth - 1],
            b: vec![false; depth - 1],
            choice_pos: 0,
            depth,
            leave_n,
            share: FE::zero(),
        }
    }

    /// Receive the message and reconstruct the tree.
    pub fn recv(&mut self, ot: &mut impl FnMut(&mut [[u8; 16]], &mut [bool], usize), s: usize) {
        ot(&mut self.m, &mut self.b, s);
        let mut share_bytes = [0u8; 32];
        self.io
            .receive_data(&mut share_bytes)
            .expect("Failed to receive share");
        self.share = FE::from_bytes_le(&share_bytes).unwrap();
    }

    /// Compute the GGM tree and reconstruct the nodes.
    pub fn compute(&mut self, ggm_tree_mem: &mut [FE], delta2: FE) {
        self.reconstruct_tree();
        self.repair_tree(ggm_tree_mem, delta2);
    }

    /// Reconstruct the GGM tree.
    fn reconstruct_tree(&mut self) {
        let mut to_fill_idx = 0;
        let mut prp = TwoKeyPRP::new([&[0u8; 16], &[0u8; 16], &[0u8; 16], &[0u8; 16]]);

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

    /// Repair the GGM tree with delta2 and local shares.
    fn repair_tree(&mut self, ggm_tree_mem: &mut [FE], delta2: FE) {
        let mut nodes_sum = FE::zero();
        for i in 0..self.leave_n {
            nodes_sum += ggm_tree_mem[i];
        }
        nodes_sum += self.share;
        nodes_sum = FE::from(0u64) - nodes_sum;

        ggm_tree_mem[self.choice_pos] = delta2 + nodes_sum;
    }

    /// Recover a single layer of the GGM tree.
    fn layer_recover(
        &mut self,
        depth: usize,
        lr: usize,
        to_fill_idx: usize,
        sum: [u8; 16],
        prp: &mut TwoKeyPRP,
    ) {
        let item_n = 1 << depth;
        let mut nodes_sum = FE::zero();

        for i in (lr..item_n).step_by(2) {
            nodes_sum += self.ggm_tree[i];
        }

        self.ggm_tree[to_fill_idx] = nodes_sum + FE::from_bytes_le(&sum).unwrap();

        if depth == self.depth - 1 {
            return;
        }

        for i in (0..item_n).rev().step_by(2) {
            prp.node_expand_2to4(
                &mut self.ggm_tree[i * 2..i * 2 + 4],
                &self.ggm_tree[i..i + 2],
            );
        }
    }

    /// Consistency check for the protocol.
    pub fn consistency_check(&mut self, io2: &mut IO, z: FE, beta: FE) {
        let digest = self.generate_digest();
        let chi = self.generate_hash_coeff(digest, self.leave_n);

        // Compute x_star
        let tmp = chi[self.choice_pos] * beta;
        let x_star = FE::from(0u64) - (z + tmp);

        // Send x_star
        io2.send_data(&x_star.to_bytes_le())
            .expect("Failed to send x_star");

        // Compute W
        let w = self.vector_inner_product_mod(&chi, &self.ggm_tree) - z;

        // Receive V and verify
        let mut v_bytes = [0u8; 32];
        io2.receive_data(&mut v_bytes).expect("Failed to receive V");
        let v = FE::from_bytes_le(&v_bytes).unwrap();

        if w != v {
            panic!("SPFSS consistency check failed!");
        }
    }

    /// Generate hash coefficients based on a seed.
    fn generate_hash_coeff(&self, seed: [u8; 16], size: usize) -> Vec<FE> {
        let mut coeffs = vec![FE::zero(); size];
        let mut prg = PRG::new(Some(&seed), 0);
        prg.random_stark252_elements(&mut coeffs);
        coeffs
    }

    /// Compute modular inner product.
    fn vector_inner_product_mod(&self, vec1: &[FE], vec2: &[FE]) -> FE {
        vec1.iter()
            .zip(vec2)
            .fold(FE::zero(), |acc, (v1, v2)| acc + (*v1 * *v2))
    }

    /// Generate digest for hash coefficients.
    fn generate_digest(&self) -> [u8; 16] {
        let mut digest = [0u8; 16];
        digest[..8].copy_from_slice(&self.share.to_bytes_le()[..8]);
        digest
    }
}
