use crate::ot::OTCO;
use crate::prg::PRG;
use crate::comm_channel::CommunicationChannel;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct Cope {
    party: u8,                     // 0 for sender, 1 for receiver
    m: usize,                      // Number of field elements
    delta: Option<FE>,             // Delta value for the sender
    delta_bool: Vec<bool>,         // Boolean representation of delta
    prg_g0: Option<Vec<PRG>>,      // PRGs for the 0-choice
    prg_g1: Option<Vec<PRG>>,      // PRGs for the 1-choice (receiver)
    mask: u128,                    // Mask for modular reduction
    powers_of_two: Vec<FE>,        // Precomputed powers of two
}

impl Cope {
    /// Create a new COPE instance.
    pub fn new(party: u8, m: usize) -> Self {
        Self {
            party,
            m,
            delta: None,
            delta_bool: vec![false; m],
            prg_g0: None,
            prg_g1: None,
            mask: u128::MAX,
            powers_of_two: vec![], // Initialize empty, will be filled in `initialize_*`
        }
    }

    /// Convert delta to a boolean array.
    fn delta_to_bool(delta: &FE, m: usize) -> Vec<bool> {
        let delta_bytes = delta.to_bytes_le();
        let mut delta_bool = vec![false; m];

        for i in 0..m {
            let byte_index = i / 8;
            let bit_index = i % 8;
            if byte_index < delta_bytes.len() {
                delta_bool[i] = (delta_bytes[byte_index] & (1 << bit_index)) != 0;
            }
        }
        delta_bool
    }

    /// Precompute powers of two in the field
    fn precompute_powers_of_two(&mut self) {
        let mut powers = vec![FE::one(); self.m];
        let base = FE::from(2);
        for i in 1..self.m {
            powers[i] = powers[i - 1] * base;
        }
        self.powers_of_two = powers;
    }

    pub fn initialize_sender<IO: CommunicationChannel>(&mut self, io: &mut IO, delta: FE) {
        self.delta = Some(delta);
        self.delta_bool = Self::delta_to_bool(&delta, self.m);
        self.precompute_powers_of_two(); // Precompute powers of two

        // Prepare keys using OTCO
        let mut k = Vec::new();
        let mut otco = OTCO::new();
        otco.recv(io, &self.delta_bool, &mut k);

        // Initialize PRGs
        self.prg_g0 = Some(
            k.iter()
                .enumerate()
                .map(|(i, key)| {
                    let mut prg = PRG::new(None, i as u64);
                    prg.reseed(key, 0);
                    prg
                })
                .collect(),
        );

        assert_eq!(k.len(), self.m, "Mismatch in key length during initialization");
        assert_eq!(self.prg_g0.as_ref().unwrap().len(), self.m, "Mismatch in prg_g0 length after initialization");
    }

    pub fn initialize_receiver<IO: CommunicationChannel>(&mut self, io: &mut IO) {
        self.precompute_powers_of_two(); // Precompute powers of two

        let mut k0 = vec![[0u8; 16]; self.m];
        let mut k1 = vec![[0u8; 16]; self.m];

        // Generate random keys
        let mut key_prg = PRG::new(None, 0);
        key_prg.random_block(&mut k0);
        key_prg.random_block(&mut k1);

        // Use OTCO to send keys
        let mut otco = OTCO::new();
        otco.send(io, &k0, &k1);

        // Initialize PRGs
        self.prg_g0 = Some(
            k0.iter()
                .enumerate()
                .map(|(i, key)| {
                    let mut prg = PRG::new(None, i as u64);
                    prg.reseed(key, 0);
                    prg
                })
                .collect(),
        );
        self.prg_g1 = Some(
            k1.iter()
                .enumerate()
                .map(|(i, key)| {
                    let mut prg = PRG::new(None, (i + self.m) as u64);
                    prg.reseed(key, 0);
                    prg
                })
                .collect(),
        );
    }

    pub fn extend_sender<IO: CommunicationChannel>(&mut self, io: &mut IO) -> FE {
        let mut w = vec![FE::zero(); self.m];

        if let Some(prgs) = &mut self.prg_g0 {
            assert_eq!(prgs.len(), self.m, "prg_g0 length does not match self.m");
            let mut w = vec![FE::zero(); self.m];
            assert_eq!(w.len(), self.m, "w length does not match self.m");

            for (i, prg) in prgs.iter_mut().enumerate() {
                assert!(i < self.m, "Index out of bounds: i = {}, self.m = {}", i, self.m);
                prg.random_stark252_elements(&mut [w[i]]);
            }
        }

        // // Generate random w values using PRGs
        // if let Some(prgs) = &mut self.prg_g0 {
        //     for (i, prg) in prgs.iter_mut().enumerate() {
        //         prg.random_stark252_elements(&mut [w[i]]);
        //     }
        // }

        // Receive v from the receiver
        let mut v = io.receive_stark252(self.m).expect("Failed to receive v");

        // Adjust v based on delta_bool
        for i in 0..self.m {
            if self.delta_bool[i] {
                v[i] = w[i] + v[i];
            } else {
                v[i] = w[i];
            }
        }

        // Aggregate v into a single field element
        self.prm2pr(&v)
    }

    pub fn extend_sender_batch<IO: CommunicationChannel>(&mut self, io: &mut IO, ret: &mut [FE], size: usize) {
        let mut w = vec![vec![FE::zero(); size]; self.m];
        let mut v = vec![vec![FE::zero(); size]; self.m];

        // Generate random w values for the batch
        if let Some(prgs) = &mut self.prg_g0 {
            for (i, prg) in prgs.iter_mut().enumerate() {
                prg.random_stark252_elements(&mut w[i]);
            }
        }

        // Receive v values from the receiver
        let received_data = io.receive_stark252(self.m * size).expect("Failed to receive v");
        for i in 0..self.m {
            for j in 0..size {
                v[i][j] = received_data[i * size + j];
            }
        }

        // Adjust v values based on delta_bool
        for i in 0..self.m {
            for j in 0..size {
                if self.delta_bool[i] {
                    v[i][j] = w[i][j] + v[i][j];
                } else {
                    v[i][j] = w[i][j];
                }
            }
        }

        // Aggregate batch results into ret
        self.prm2pr_batch(ret, &v);
    }

    pub fn extend_receiver<IO: CommunicationChannel>(&mut self, io: &mut IO, u: FE) -> FE {
        let mut w0 = vec![FE::zero(); self.m];
        let mut w1 = vec![FE::zero(); self.m];
        let mut tau = vec![FE::zero(); self.m];

        // Generate random w0 and w1 values
        if let (Some(prgs_g0), Some(prgs_g1)) = (&mut self.prg_g0, &mut self.prg_g1) {
            for i in 0..self.m {
                prgs_g0[i].random_stark252_elements(&mut [w0[i]]);
                prgs_g1[i].random_stark252_elements(&mut [w1[i]]);

                w1[i] = w1[i] + u;
                tau[i] = w0[i] - w1[i];
            }
        }

        // Send tau to the sender
        io.send_stark252(&tau).expect("Failed to send tau");

        // Aggregate w0 into a single field element
        self.prm2pr(&w0)
    }

    pub fn extend_receiver_batch<IO: CommunicationChannel>(&mut self, io: &mut IO, ret: &mut [FE], u: &[FE], size: usize) {
        let mut w0 = vec![vec![FE::zero(); size]; self.m];
        let mut w1 = vec![vec![FE::zero(); size]; self.m];
        let mut tau = vec![vec![FE::zero(); size]; self.m];

        let start = Instant::now();


        // Generate random w0 and w1 values
        if let (Some(prgs_g0), Some(prgs_g1)) = (&mut self.prg_g0, &mut self.prg_g1) {
            for i in 0..self.m {
                prgs_g0[i].random_stark252_elements(&mut w0[i]);
                prgs_g1[i].random_stark252_elements(&mut w1[i]);

                for j in 0..size {
                    w1[i][j] = w1[i][j] + u[j];
                    tau[i][j] = w0[i][j] - w1[i][j];
                }
            }
        }

        let duration = start.elapsed();
        println!("Time to generate {} random elements: {:?}", self.m * size * 2, duration);


        // Send tau to the sender
        let tau_flat: Vec<FE> = tau.iter().flat_map(|row| row.iter().cloned()).collect();
        // println!("The number of elements in tau_flat sent: {:?}", tau_flat.clone().len());

        // assert_eq!(tau_flat.clone().len(), self.m * size, "tau_flat mismatch type");

        io.send_stark252(&tau_flat).expect("Failed to send tau");

        // Aggregate w0 batch results into ret
        self.prm2pr_batch(ret, &w0);
    }


    /// Aggregates a vector of field elements into a single field element using precomputed powers of two.
    fn prm2pr(&self, elements: &[FE]) -> FE {
        elements
            .iter()
            .zip(&self.powers_of_two)
            .fold(FE::zero(), |acc, (e, power)| acc + (*e * *power))
    }

    /// Aggregates a batch of vectors of field elements into a result array using precomputed powers of two.
    fn prm2pr_batch(&self, ret: &mut [FE], elements: &[Vec<FE>]) {
        for (j, result) in ret.iter_mut().enumerate() {
            *result = elements.iter().zip(&self.powers_of_two).fold(FE::zero(), |acc, (row, power)| {
                acc + (row[j] * *power)
            });
        }
    }

    /// Consistency check function where `a` has only one `FE`
    pub fn check_triple<IO: CommunicationChannel>(&mut self, io: &mut IO, a: &[FE], b: &[FE], sz: usize) {
        if self.party == 0 {
            // Sender's role
            io.send_stark252(a).expect("Failed to send `a` in check_triple");
            io.send_stark252(b).expect("Failed to send `b` in check_triple");
        } else {
            // Receiver's role
            let delta = io.receive_stark252(1).expect("Failed to receive `delta` in check_triple")[0];
            let c = io.receive_stark252(sz).expect("Failed to receive `c` in check_triple");

            // Perform the consistency check
            for i in 0..sz {
                // let tmp = b[i] - (delta * c[i]); // Rearranged: b[i] == delta * c[i]
                if b[i] != a[i] * delta + c[i] {
                    eprintln!("Consistency check failed at index {}", i);
                    panic!("Consistency check failed");
                }
            }
            println!("Consistency check passed");
        }
    }
}
