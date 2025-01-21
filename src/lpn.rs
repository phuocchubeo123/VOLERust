use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use std::sync::{Arc, Mutex};
use rayon::prelude::*; // For parallel processing

type F = Stark252PrimeField;
type FE = FieldElement<F>;

pub struct LpnFp {
    party: usize, // 0: Alice (sender), 1: Bob (receiver)
    k: usize,     // Security parameter
    n: usize,     // Total number of elements
    threads: usize, // Number of threads
    k_mask: usize, // Bitmask for modular reduction
    seed: u64,     // PRNG seed (placeholder)

    m: Arc<Mutex<Vec<FE>>>, // Shared receiver array
    k_arr: Arc<Mutex<Vec<FE>>>, // Shared sender array
    prem: Vec<FE>, // Precomputed receiver data
    prek: Vec<FE>, // Precomputed sender data
}

impl LpnFp {
    /// Creates a new LpnFp instance
    pub fn new(
        n: usize,
        k: usize,
        threads: usize,
        prem: Vec<FE>,
        prek: Vec<FE>,
        seed: u64,
    ) -> Self {
        let k_mask = (1 << (k.next_power_of_two().trailing_zeros() as usize)) - 1;
        Self {
            party: 0,
            k,
            n,
            threads,
            k_mask,
            seed,
            m: Arc::new(Mutex::new(vec![FE::zero(); n])),
            k_arr: Arc::new(Mutex::new(vec![FE::zero(); n])),
            prem,
            prek,
        }
    }

    /// Perform single addition for the receiver
    pub fn add2_single(&self, idx1: usize, idx2: &[usize]) {
        let mut m_guard = self.m.lock().unwrap();
        let mut m_idx1 = m_guard[idx1];
        for &j in &idx2[..5] {
            m_idx1 += self.prem[j];
        }
        m_idx1 = m_idx1.reduce();
        for &j in &idx2[5..] {
            m_idx1 += self.prem[j];
        }
        m_guard[idx1] = m_idx1.reduce();
    }

    /// Perform single addition for the sender
    pub fn add1_single(&self, idx1: usize, idx2: &[usize]) {
        let mut k_guard = self.k_arr.lock().unwrap();
        let mut k_idx1 = k_guard[idx1];
        for &j in &idx2[..5] {
            k_idx1 += self.prek[j];
        }
        k_idx1 = k_idx1.reduce();
        for &j in &idx2[5..] {
            k_idx1 += self.prek[j];
        }
        k_guard[idx1] = k_idx1.reduce();
    }

    /// Perform batch addition for the receiver
    pub fn add2(&self, idx1: usize, idx2: &[usize]) {
        let mut m_guard = self.m.lock().unwrap();
        let mut tmp = [FE::zero(); 4];
        for i in 0..4 {
            tmp[i] = m_guard[idx1 + i];
        }
        for &j in &idx2[..5] {
            tmp.iter_mut().for_each(|x| *x += self.prem[j]);
        }
        tmp.iter_mut().for_each(|x| *x = x.reduce());
        for &j in &idx2[5..] {
            tmp.iter_mut().for_each(|x| *x += self.prem[j]);
        }
        for i in 0..4 {
            m_guard[idx1 + i] = tmp[i].reduce();
        }
    }

    /// Perform batch addition for the sender
    pub fn add1(&self, idx1: usize, idx2: &[usize]) {
        let mut k_guard = self.k_arr.lock().unwrap();
        let mut tmp = [FE::zero(); 4];
        for i in 0..4 {
            tmp[i] = k_guard[idx1 + i];
        }
        for &j in &idx2[..5] {
            tmp.iter_mut().for_each(|x| *x += self.prek[j]);
        }
        tmp.iter_mut().for_each(|x| *x = x.reduce());
        for &j in &idx2[5..] {
            tmp.iter_mut().for_each(|x| *x += self.prek[j]);
        }
        for i in 0..4 {
            k_guard[idx1 + i] = tmp[i].reduce();
        }
    }

    /// Main compute task for parallel execution
    pub fn task(&self, start: usize, end: usize) {
        let mut prng = self.seed; // Placeholder for PRP
        for i in start..end {
            let indices: Vec<usize> = (0..10)
                .map(|_| (prng as usize) & self.k_mask) // Replace with actual PRP
                .collect();
            if self.party == 1 {
                self.add2_single(i, &indices);
            } else {
                self.add1_single(i, &indices);
            }
            prng = prng.wrapping_mul(6364136223846793005).wrapping_add(1); // Simple LCG for PRNG
        }
    }

    /// Main compute loop with parallelism
    pub fn compute(&self) {
        let chunk_size = self.n / self.threads;
        (0..self.threads).into_par_iter().for_each(|thread_idx| {
            let start = thread_idx * chunk_size;
            let end = if thread_idx == self.threads - 1 {
                self.n
            } else {
                start + chunk_size
            };
            self.task(start, end);
        });
    }
}
