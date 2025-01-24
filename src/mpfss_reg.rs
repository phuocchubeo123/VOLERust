use crate::prg::PRG;
use crate::preot::OTPre;
use crate::comm_channel::CommunicationChannel;
use crate::spfss_sender::SpfssSenderFp;
use crate::spfss_receiver::SpfssRecverFp;
use crate::hash::Hash;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

// No multithreading
pub struct MpfssReg {
    party: usize,
    item_n: usize,
    idx_max: usize, 
    m: usize,
    tree_height: usize,
    leave_n: usize,
    tree_n: usize,
    is_malicious: bool,
    prg: PRG,
    secret_share_x: FE,
    ggm_tree: Vec<Vec<FE>>,
    check_chialpha_buf: Vec<FE>,
    check_vw_buf: Vec<FE>,
    item_pos_receiver: Vec<usize>,
    triple_yz: Vec<FE>,
}

impl MpfssReg {
    pub fn new<const n: usize, const t: usize, const log_bin_sz: usize>(party: usize) -> Self {
        // make sure n = t * leave_n
        Self {
            party: party,
            item_n: t,
            idx_max: n,
            m: 0,
            tree_height: log_bin_sz + 1,
            leave_n: 1 << log_bin_sz,
            tree_n: t,
            is_malicious: false,
            prg: PRG::new(None, 0),
            secret_share_x: FE::zero(),
            ggm_tree: vec![vec![FE::zero();t]; 1 << log_bin_sz],
            check_chialpha_buf: vec![FE::zero(); t],
            check_vw_buf: vec![FE::zero(); t],
            item_pos_receiver: vec![0; t],
            triple_yz: vec![FE::zero(); t+1],
        }
    }

    pub fn set_malicious(&mut self) {
        self.is_malicious = true;
    }

    pub fn sender_init(&mut self, delta: FE) {
        self.secret_share_x = delta.clone();
    }

    pub fn receiver_init(&mut self) {
    }

    pub fn set_vec_x(&self, out_vec: &mut [FE], in_vec: &[FE]) {
        for i in 0..self.tree_n {
            let pt = i * self.leave_n + self.item_pos_receiver[i] % self.leave_n;
            // not sure, check the math later
            out_vec[pt] += in_vec[i];
        }
    }

    pub fn mpfss<IO: CommunicationChannel>(&mut self, io: &mut IO, ot: &mut OTPre, triple_yz: &[FE], sparse_vector: &mut [FE]) {
        self.triple_yz.copy_from_slice(triple_yz);
        if self.party == 0 {
            self.mpfss_sender(io, ot, sparse_vector);
        } else {
            self.mpfss_receiver(io, ot, sparse_vector);
        }

    }

    pub fn mpfss_sender<IO: CommunicationChannel>(&mut self, io: &mut IO, ot: &mut OTPre, sparse_vector: &mut [FE]) {
        // Set up PreOT first
        for i in 0..self.tree_n {
            ot.choices_sender(io);
        }
        ot.reset();

        // Now start doing Spfss
        for i in 0..self.tree_n {
            let mut sender = SpfssSenderFp::new(self.tree_height);
            sender.compute(&mut self.ggm_tree[i], self.secret_share_x, self.triple_yz[i]);
            sender.send(io, ot, i);
            sparse_vector[i*self.leave_n..(i+1)*self.leave_n].copy_from_slice(&self.ggm_tree[i]);

            // Malicious check
            if self.is_malicious {
                let mut seed = vec![FE::zero(); 1];
                self.seed_expand(io, &mut seed, 1);
                sender.consistency_check_msg_gen(&mut self.check_vw_buf[i], io, seed[0]);

            }
        }

        // consistency batch check
        if self.is_malicious {
            let x_star = io.receive_stark252(1).expect("Failed to receive x_star")[0];
            let tmp = self.secret_share_x * x_star + self.triple_yz[self.tree_n];
            let mut vb = FE::zero();
            vb = vb - tmp;
            for i in 0..self.tree_n {
                vb += self.check_vw_buf[i];
            }

            let hash = Hash::new();
            let digest = hash.hash_32byte_block(&vb.to_bytes_le());
            let h = FE::from_bytes_le(&digest).unwrap();
            io.send_stark252(&[h]).expect("Failed to send h");
        }
    }

    pub fn mpfss_receiver<IO: CommunicationChannel>(&mut self, io: &mut IO, ot: &mut OTPre, sparse_vector: &mut [FE]) {
        for i in 0..self.tree_n {
            let b = vec![false; self.tree_height - 1];
            ot.choices_recver(io, &b);
        }
        ot.reset();

        for i in 0..self.tree_n {
            let mut receiver = SpfssRecverFp::new(self.tree_height);
            self.item_pos_receiver[i] = receiver.get_index();
            receiver.recv(io, ot, i);
            receiver.compute(&mut self.ggm_tree[i], self.triple_yz[i]);
            sparse_vector[i*self.leave_n..(i+1)*self.leave_n].copy_from_slice(&self.ggm_tree[i]);

            if self.is_malicious {
                let mut seed = vec![FE::zero(); 1];
                self.seed_expand(io, &mut seed, 1);
                receiver.consistency_check_msg_gen(&mut self.check_chialpha_buf[i], &mut self.check_vw_buf[i], io, self.triple_yz[i], seed[0]);
            }
        }

        if self.is_malicious {
            let mut beta_mul_chialpha = FE::zero();
            for i in 0..self.tree_n {
                beta_mul_chialpha += self.check_chialpha_buf[i] * self.triple_yz[i];
            }
            let x_star = self.triple_yz[self.tree_n] - beta_mul_chialpha;
            io.send_stark252(&[x_star]).expect("Cannot send x_star.");

            let mut va = FE::zero();
            va = va - self.triple_yz[self.tree_n];
            for i in 0..self.tree_n {
                va += self.check_vw_buf[i];
            }

            let hash = Hash::new();
            let digest = hash.hash_32byte_block(&va.to_bytes_le());
            let h = FE::from_bytes_le(&digest).unwrap();

            let r = io.receive_stark252(1).expect("Cound not receive h from Sender")[0];

            if r != h {
                panic!("Consistency check for Mpfss failed!");
            } else {
                println!("Consistency check for Mpfss successful!");
            }
        }

    }

    pub fn seed_expand<IO: CommunicationChannel>(&mut self, io: &mut IO, seed: &mut [FE], threads: usize) {
        let mut sd = [0u8; 16];
        if self.party == 0 {
            sd = io.receive_data()[0];
        } else {
            let mut sd_buf = vec![[0u8; 16]; 1];
            self.prg.random_block(&mut sd_buf);
            sd = sd_buf[0].clone();
            io.send_data(&[sd]);
        }
        let mut prg2 = PRG::new(Some(&sd), 0);
        prg2.random_stark252_elements(seed);
    }
}
