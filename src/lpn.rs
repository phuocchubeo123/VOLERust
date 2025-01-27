use crate::prp::{PRP, LubyRackoffPRP, FieldPRP};
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct Lpn {
    party: usize,
    k: usize, 
    n: usize,
    seed: [u8; 16],
    seed_field: [u8; 32],
    M: Vec<FE>,
    preM: Vec<FE>,
    // prex: Vec<FE>,
    K: Vec<FE>,
    preK: Vec<FE>,
}

impl Lpn {
    pub fn new(k: usize, n: usize, seed: &[u8; 16], seed_field: &[u8; 32]) -> Self {
        Self {
            party: 0,
            k: k,
            n: n,
            seed: *seed,
            seed_field: *seed_field,
            M: vec![FE::zero(); n],
            preM: vec![FE::zero(); k],
            K: vec![FE::zero(); n],
            preK: vec![FE::zero(); k],
        }
    }

    pub fn compute_K(&mut self) {
        let prp = PRP::new(Some(&self.seed));
        // let field_prp = LubyRackoffPRP::new(Some(&self.seed_field));
        let field_prp = FieldPRP::new(Some(&self.seed_field));
        for i in 0..self.n {
            let mut tmp = vec![[0u8; 16]; 10];
            let mut tmp2 = vec![[0u8; 32]; 10];
            for m in 0..10 {
                tmp[m][0..8].copy_from_slice(&i.to_le_bytes());
                tmp[m][8..].copy_from_slice(&(m as usize).to_le_bytes());
                tmp2[m][0..8].copy_from_slice(&i.to_le_bytes());
                tmp2[m][8..16].copy_from_slice(&(m as usize).to_le_bytes());
            }

            prp.permute_block(&mut tmp, 10);
            let r: Vec<usize> = tmp
                .iter()
                .map(|x| ((u128::from_le_bytes(*x) >> 64) as usize) % self.k)
                .collect();

            let mut tmp_field: Vec<_> = tmp2
                .iter()
                .map(|x| FE::from_bytes_le(x).expect("Cannot get FE from bytes"))
                .collect();
            field_prp.permute_block(&mut tmp_field, 10);

            for m in 0..10 {
                self.K[i] += tmp_field[m] * self.preK[r[m]];
            }
        }
    }

    pub fn compute_K_and_M(&mut self) {
        let prp = PRP::new(Some(&self.seed));
        // let field_prp = LubyRackoffPRP::new(Some(&self.seed_field));
        let field_prp = FieldPRP::new(Some(&self.seed_field));
        for i in 0..self.n {
            let mut tmp = vec![[0u8; 16]; 10];
            let mut tmp2 = vec![[0u8; 32]; 10];
            for m in 0..10 {
                tmp[m][0..8].copy_from_slice(&i.to_le_bytes());
                tmp[m][8..].copy_from_slice(&(m as usize).to_le_bytes());
                tmp2[m][0..8].copy_from_slice(&i.to_le_bytes());
                tmp2[m][8..16].copy_from_slice(&(m as usize).to_le_bytes());
            }

            prp.permute_block(&mut tmp, 10);
            let r: Vec<usize> = tmp
                .iter()
                .map(|x| ((u128::from_le_bytes(*x) >> 64) as usize) % self.k)
                .collect();


            let mut tmp_field: Vec<_> = tmp2
                .iter()
                .map(|x| FE::from_bytes_le(x).expect("Cannot get FE from bytes"))
                .collect();
            field_prp.permute_block(&mut tmp_field, 10);

            for m in 0..10 {
                self.K[i] += tmp_field[m] * self.preK[r[m]];
                self.M[i] += tmp_field[m] * self.preM[r[m]];
            }
        }
    }

    pub fn compute_send(&mut self, K: &mut [FE], kkK: &[FE]) {
        self.party = 0;
        self.K.copy_from_slice(K);
        self.preK.copy_from_slice(kkK);
        self.compute_K();
        K.copy_from_slice(&self.K);
    }

    pub fn compute_recv(&mut self, K: &mut [FE], M: &mut [FE], kkK: &[FE], kkM: &[FE]) {
        self.party = 1;
        self.K.copy_from_slice(K);
        self.preK.copy_from_slice(kkK);
        self.M.copy_from_slice(M);
        self.preM.copy_from_slice(kkM);
        self.compute_K_and_M();
        K.copy_from_slice(&self.K);
        M.copy_from_slice(&self.M);
    }
}