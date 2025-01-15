use crate::twokeyprp::TwoKeyPRP;
use crate::prg::PRG;
use crate::comm_channel::CommunicationChannel;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct SpfssSenderFp<'a, IO> {
    io: &'a mut IO,
    seed: [u8; 16],
    delta: FE,
    secret_sum: FE,
    ggm_tree: Vec<FE>,
    m: Vec<[u8; 16]>,
    depth: usize,
    leave_n: usize,
    prg: PRG,
}

impl<'a, IO: CommunicationChannel> SpfssSenderFp<'a, IO> {
    /// Create a new SpfssSenderFp instance.
    pub fn new(io: &'a mut IO, depth: usize) -> Self {
        let leave_n = 1 << (depth - 1);
        let mut prg = PRG::new(None, 0);
        let mut seed = [0u8; 16];
        prg.random_block(&mut [seed]);
        Self {
            io,
            seed,
            delta: FE::zero(),
            secret_sum: FE::zero(),
            ggm_tree: vec![FE::zero(); leave_n],
            m: vec![[0u8; 16]; depth - 1],
            depth,
            leave_n,
            prg,
        }
    }

    /// Generate GGM tree and prepare messages for OT.
    pub fn compute(&mut self, ggm_tree_mem: &mut [FE], secret: FE, gamma: FE) {
        self.delta = secret.clone();
        self.ggm_tree_gen(ggm_tree_mem, secret, gamma);
    }

    /// Send OT messages and secret sum.
    pub fn send(&mut self, ot: &mut impl FnMut(&[[u8; 16]], &[[u8; 16]], usize), s: usize) {
        let (ot_msg_0, ot_msg_1) = self.m.split_at(self.depth - 1);
        ot(ot_msg_0, ot_msg_1, s);
        self.io
            .send_data(&self.secret_sum.to_bytes_le())
            .expect("Failed to send secret_sum");
    }

    /// Generate the GGM tree from the top.
    fn ggm_tree_gen(&mut self, ggm_tree_mem: &mut [FE], secret: FE, gamma: FE) {
        let mut prp = TwoKeyPRP::new([&self.seed, &[0u8; 16], &[0u8; 16], &[0u8; 16]]);
        self.ggm_tree = vec![FE::zero(); self.leave_n];

        // Generate the first layer of the GGM tree
        prp.node_expand_1to2(&mut ggm_tree_mem[..2], &secret);

        // Process all layers
        for h in 1..self.depth - 1 {
            let mut ot_msg_0 = FE::zero();
            let mut ot_msg_1 = FE::zero();
            let sz = 1 << h;
            for i in (0..sz).step_by(2) {
                prp.node_expand_2to4(&mut ggm_tree_mem[i * 2..(i * 2 + 4)], &ggm_tree_mem[i..(i + 2)]);
                ot_msg_0 += ggm_tree_mem[i * 2] + ggm_tree_mem[i * 2 + 2];
                ot_msg_1 += ggm_tree_mem[i * 2 + 1] + ggm_tree_mem[i * 2 + 3];
            }
            self.m[h - 1] = ot_msg_0.to_bytes_le();
            self.m[h - 1] = ot_msg_1.to_bytes_le();
        }

        // Compute the secret sum
        self.secret_sum = FE::zero();
        for node in ggm_tree_mem.iter().take(self.leave_n) {
            self.secret_sum += *node;
        }
        self.secret_sum = FE::from(0u64) - self.secret_sum + gamma;
    }

    /// Consistency check: Protocol PI_spsVOLE
    pub fn consistency_check(&mut self, io2: &mut IO, y: FE) {
        let digest = self.generate_digest();
        let chi = self.generate_hash_coeff(digest, self.leave_n);

        // Receive x_star
        let x_star_bytes = io2.receive_data(32).expect("Failed to receive x_star");
        let x_star = FE::from_bytes_le(&x_star_bytes).unwrap();

        // Compute y_star
        let tmp = x_star * self.delta;
        let y_star = y + (FE::from(0u64) - tmp);

        // Compute V
        let v = self.vector_inner_product_mod(&chi, &self.ggm_tree) - y_star;

        // Send V
        io2.send_data(&v.to_bytes_le()).expect("Failed to send V");
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
        digest[..8].copy_from_slice(&self.secret_sum.to_bytes_le()[..8]);
        digest
    }
}
