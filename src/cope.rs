use crate::PRG;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;

/// Alias for the STARK-252 prime field and its field element.
pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct Cope<IO> {
    party: u8,               // 0 for sender, 1 for receiver
    m: usize,                // Number of field elements
    delta: Option<FE>,       // Delta value for the sender
    delta_bool: Vec<bool>,   // Boolean representation of delta
    prg_g0: Option<Vec<PRG>>, // PRGs for the 0-choice
    prg_g1: Option<Vec<PRG>>, // PRGs for the 1-choice (receiver)
    otco: OTCO<IO>,          // Oblivious transfer communication
}

impl<IO> Cope<IO>
where
    IO: IOChannel,
{
    /// Create a new COPE instance.
    pub fn new(party: u8, m: usize, otco: OTCO<IO>) -> Self {
        Cope {
            party,
            m,
            delta: None,
            delta_bool: vec![false; m],
            prg_g0: None,
            prg_g1: None,
            otco,
        }
    }

    /// Sender's initialization with delta.
    pub fn initialize_sender(&mut self, delta: FE) {
        self.delta = Some(delta);

        // Convert delta to a boolean array representation
        self.delta_bool = Self::delta_to_bool(&delta, self.m);

        // Initialize PRGs for the sender
        let mut prgs = Vec::with_capacity(self.m);
        for i in 0..self.m {
            let mut prg = PRG::new(None, i as u64);
            prg.reseed(&[0u8; 16], i as u64); // Placeholder seed
            prgs.push(prg);
        }
        self.prg_g0 = Some(prgs);

        // Send initialization data to the receiver
        self.otco.io.send_data(&delta.to_bytes_le());
        self.otco.io.flush();
    }

    /// Receiver's initialization.
    pub fn initialize_receiver(&mut self) {
        let mut delta_bytes = vec![0u8; FE::FIELD_SIZE];
        self.otco.io.receive_data(&mut delta_bytes);
        let delta = FE::from_bytes_le(&delta_bytes).unwrap();
        println!("Receiver received delta: {}", delta);

        // Initialize PRGs for the receiver
        let mut prgs_g0 = Vec::with_capacity(self.m);
        let mut prgs_g1 = Vec::with_capacity(self.m);

        for i in 0..self.m {
            let mut prg_g0 = PRG::new(None, i as u64);
            prg_g0.reseed(&[0u8; 16], i as u64); // Placeholder seed
            prgs_g0.push(prg_g0);

            let mut prg_g1 = PRG::new(None, (i + self.m) as u64);
            prg_g1.reseed(&[0u8; 16], (i + self.m) as u64); // Placeholder seed
            prgs_g1.push(prg_g1);
        }
        self.prg_g0 = Some(prgs_g0);
        self.prg_g1 = Some(prgs_g1);
    }

    /// Sender's extend operation.
    pub fn extend_sender(&mut self) -> Vec<FE> {
        let mut w = vec![FE::zero(); self.m];
        let mut v = vec![FE::zero(); self.m];

        if let Some(prgs) = &mut self.prg_g0 {
            // Generate random values using PRGs
            for (i, prg) in prgs.iter_mut().enumerate() {
                prg.random_stark252_elements(&mut [w[i]]);
            }
        }

        // Send `w` to the receiver
        for element in &w {
            self.otco.io.send_data(&element.to_bytes_le());
        }
        self.otco.io.flush();

        // Adjust `w` with delta to compute `v`
        for (i, delta_bool) in self.delta_bool.iter().enumerate() {
            if *delta_bool {
                v[i] = w[i] + self.delta.unwrap();
            } else {
                v[i] = w[i];
            }
        }

        v
    }

    /// Receiver's extend operation.
    pub fn extend_receiver(&mut self, u: FE) -> Vec<FE> {
        let mut w0 = vec![FE::zero(); self.m];
        let mut w1 = vec![FE::zero(); self.m];
        let mut tau = vec![FE::zero(); self.m];

        if let Some(prgs_g0) = &mut self.prg_g0 {
            if let Some(prgs_g1) = &mut self.prg_g1 {
                // Receive `w` from the sender
                for element in &mut w0 {
                    let mut element_bytes = vec![0u8; FE::FIELD_SIZE];
                    self.otco.io.receive_data(&mut element_bytes);
                    *element = FE::from_bytes_le(&element_bytes).unwrap();
                }

                // Compute `tau`
                for i in 0..self.m {
                    prgs_g1[i].random_stark252_elements(&mut [w1[i]]);
                    w1[i] = w1[i] + u;
                    tau[i] = w0[i] + w1[i];
                }
            }
        }

        tau
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
}
