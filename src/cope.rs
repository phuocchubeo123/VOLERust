use crate::ot::OTCO;
use crate::prg::PRG;
use crate::comm_channel::CommunicationChannel;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct Cope<IO> {
    party: u8,                     // 0 for sender, 1 for receiver
    m: usize,                      // Number of field elements
    delta: Option<FE>
    delta_bool: Vec<bool>,         // Boolean representation of delta
    prg_g0: Option<Vec<PRG>>,      // PRGs for the 0-choice
    prg_g1: Option<Vec<PRG>>,      // PRGs for the 1-choice (receiver)
    io: IO
    mask: u128,                    // Mask for modular reduction
}

impl<IO: CommunicationChannel> Cope<IO>
{
    /// Create a new COPE instance.
    pub fn new(party: u8, io: IO) -> Self {
        Self {
            party,
            m,
            delta: None,
            delta_bool: vec![false; m],
            prg_g0: None,
            prg_g1: None,
            io,
            mask: u128::MAX,
        }
    }

    /// Convert delta to a boolean array.
    fn delta_to_bool(delta: &FE, m: usize) -> Vec<bool> {
        let mut delta_bytes = delta.to_bytes_le();
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

    pub fn initialize_sender(&mut self, delta: FE) {
        self.delta = Some(delta);
        self.delta_bool = Self::delta_to_bool(&delta, self.m);

        // Prepare keys using OTCO
        let mut k = vec![[0u8; 16]; self.m];
        let mut otco = OTCO::new(io);
        otco.recv(&self.delta_bool, &mut k);

        // Initialize or update PRGs in-place
        match &mut self.prg_g0 {
            Some(prgs) => {
                // Reuse existing PRG objects
                for (i, prg) in prgs.iter_mut().enumerate() {
                    prg.reseed(&k[i], 0);
                }
            }
            None => {
                // Initialize PRGs if not already present
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
            }
        }
    }

    pub fn initialize_receiver(&mut self, io: &mut IO) {
        let mut k0 = vec![[0u8; 16]; self.m];
        let mut k1 = vec![[0u8; 16]; self.m];

        // Generate random keys
        // Create a separate PRG to initialize k0 and k1
        let mut key_prg = PRG::new(None, 0);
        key_prg.random_block(&mut k0);
        key_prg.random_block(&mut k1);

        // Use OTCO to send keys
        let mut otco = OTCO::new(io);
        otco.send(&k0, &k1);

        // Initialize or update PRGs in-place
        match (&mut self.prg_g0, &mut self.prg_g1) {
            (Some(prgs_g0), Some(prgs_g1)) => {
                // Reuse existing PRG objects
                for i in 0..self.m {
                    prgs_g0[i].reseed(&k0[i], 0);
                    prgs_g1[i].reseed(&k1[i], 0);
                }
            }
            (None, None) => {
                // Initialize PRGs if not already present
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
            _ => panic!("prg_g0 and prg_g1 should either both exist or both be None"),
        }
    }

    pub fn extend_sender(&mut self) -> FE {
        let mut w = vec![FE::zero(); self.m];
        let mut v = vec![FE::zero(); self.m];

        // Generate random w values using PRGs
        if let Some(prgs) = &mut self.prg_g0 {
            for (i, prg) in prgs.iter_mut().enumerate() {
                prg.random_stark252_elements(&mut [w[i]]);
            }
        }

        // Receive v from the receiver
        v = self.io.receive_stark252(self.m).expect("Failed to receive v");

        // Adjust v based on delta_bool
        for i in 0..self.m {
            if self.delta_bool[i] {
                v[i] = w[i] + v[i];
            } else {
                v[i] = w[i];
            }
        }

        // Aggregate v into a single field element
        Self::prm2pr(&v)
    }

    pub fn extend_sender_batch(&mut self, ret: &mut [FE], size: usize) {
        let mut w = vec![vec![FE::zero(); size]; self.m];
        let mut v = vec![vec![FE::zero(); size]; self.m];

        // Generate random w values for the batch
        if let Some(prgs) = &mut self.prg_g0 {
            for (i, prg) in prgs.iter_mut().enumerate() {
                prg.random_stark252_elements(&mut w[i]);
            }
        }

        // Receive v values from the receiver
        let received_data = self
            .io
            .receive_stark252(self.m * size)
            .expect("Failed to receive v");
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
        Self::prm2pr_batch(ret, &v);
    }

    pub fn extend_receiver(&mut self, u: FE) -> FE {
        let mut w0 = vec![FE::zero(); self.m];
        let mut w1 = vec![FE::zero(); self.m];
        let mut tau = vec![FE::zero(); self.m];

        // Generate random w0 and w1 values
        if let (Some(prgs_g0), Some(prgs_g1)) = (&mut self.prg_g0, &mut self.prg_g1) {
            for i in 0..self.m {
                prgs_g0[i].random_stark252_elements(&mut [w0[i]]);
                prgs_g1[i].random_stark252_elements(&mut [w1[i]]);

                w1[i] = w1[i] + u;
                tau[i] = w0[i] + w1[i];
            }
        }

        // Send tau to the sender
        self.io
            .send_stark252(&tau)
            .expect("Failed to send tau");

        // Aggregate w0 into a single field element
        Self::prm2pr(&w0)
    }

    pub fn extend_receiver_batch(&mut self, ret: &mut [FE], u: &[FE], size: usize) {
        let mut w0 = vec![vec![FE::zero(); size]; self.m];
        let mut w1 = vec![vec![FE::zero(); size]; self.m];
        let mut tau = vec![vec![FE::zero(); size]; self.m];

        // Generate random w0 and w1 values
        if let (Some(prgs_g0), Some(prgs_g1)) = (&mut self.prg_g0, &mut self.prg_g1) {
            for i in 0..self.m {
                prgs_g0[i].random_stark252_elements(&mut w0[i]);
                prgs_g1[i].random_stark252_elements(&mut w1[i]);

                for j in 0..size {
                    w1[i][j] = w1[i][j] + u[j];
                    tau[i][j] = w0[i][j] + w1[i][j];
                }
            }
        }

        // Send tau to the sender
        let tau_flat: Vec<FE> = tau.iter().flat_map(|row| row.iter().cloned()).collect();
        self.io
            .send_stark252(&tau_flat)
            .expect("Failed to send tau");

        // Aggregate w0 batch results into ret
        Self::prm2pr_batch(ret, &w0);
    }

    /// Aggregates a vector of field elements into a single field element.
    fn prm2pr(elements: &[FE]) -> FE {
        elements.iter().enumerate().fold(FE::zero(), |acc, (i, e)| {
            acc + (*e << i)
        })
    }

    /// Aggregates a batch of vectors of field elements into a result array.
    fn prm2pr_batch(ret: &mut [FE], elements: &[Vec<FE>]) {
        for (j, result) in ret.iter_mut().enumerate() {
            *result = elements.iter().enumerate().fold(FE::zero(), |acc, (i, row)| {
                acc + (row[j] << i)
            });
        }
    }

    /// Consistency check function
    pub fn check_triple(&mut self, a: &[u64], b: &[FE], sz: usize) {
        if self.party == 0 {
            // Sender's role
            // Serialize and send `a` and `b` to the receiver
            let a_bytes: Vec<[u8; 16]> = a
                .iter()
                .map(|val| {
                    let mut bytes = [0u8; 16];
                    bytes[..8].copy_from_slice(&val.to_le_bytes());
                    bytes
                })
                .collect();

            self.io
                .send_data(&a_bytes)
                .expect("Failed to send `a` in check_triple");
            self.io
                .send_stark252(b)
                .expect("Failed to send `b` in check_triple");
        } else {
            // Receiver's role
            // Receive `delta` and `c` from the sender
            let mut delta_buf = [0u8; 8];
            self.io
                .receive_data(&mut delta_buf)
                .expect("Failed to receive `delta` in check_triple");
            let delta = u64::from_le_bytes(delta_buf);

            let c = self
                .io
                .receive_stark252(sz)
                .expect("Failed to receive `c` in check_triple");

            // Perform the consistency check
            for i in 0..sz {
                let tmp = a[i] as u128 * delta as u128; // a[i] * delta
                let tmp = FE::from(tmp) + &c[i];        // (a[i] * delta) + c[i]

                if tmp != b[i] {
                    eprintln!("Consistency check failed at index {}", i);
                    panic!("Consistency check failed");
                }
            }
            println!("Consistency check passed");
        }
    }
}
