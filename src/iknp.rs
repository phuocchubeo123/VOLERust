use crate::ot::OTCO;
use crate::comm_channel::CommunicationChannel;
use crate::prg::PRG;
use std::convert::TryInto;

const BLOCK_SIZE: usize = 1024 * 2;
const NUM_BITS: usize = 128;


pub struct IKNP<'a, IO: CommunicationChannel> {
    base_ot: Option<OTCO<'a, IO>>,
    delta: Option<[u8; 16]>,
    setup: bool,
    s: [bool; NUM_BITS],
    local_r: [bool; 256],
    local_out: Vec<[u8; 16]>,
    g0: Option<Vec<PRG>>,
    g1: Option<Vec<PRG>>,
    malicious: bool,
    k0: Vec<[u8; 16]>,
    k1: Vec<[u8; 16]>,
}

impl<'a, IO: CommunicationChannel> IKNP<'a, IO> {
    pub fn new(io: &'a mut IO, malicious: bool) -> Self {
        Self {
            base_ot: Some(OTCO::new(io)),
            delta: None,
            setup: false,
            s: [false; NUM_BITS],
            local_r: [false; 256],
            local_out: vec![[0u8; 16]; BLOCK_SIZE],
            g0: None,
            g1: None,
            malicious,
            k0: vec![[0u8; 16]; NUM_BITS],
            k1: vec![[0u8; 16]; NUM_BITS],
        }
    }

    pub fn setup_send(&mut self, in_s: Option<&[bool]>, in_k0: Option<&[[u8; 16]]>) {
        self.setup = true;

        if let Some(in_s) = in_s {
            self.s.copy_from_slice(in_s);
        } else {
            let mut prg = PRG::new(None, 0);
            prg.random_bool_array(&mut self.s);
        }

        if let Some(in_k0) = in_k0 {
            self.k0.copy_from_slice(in_k0);
        } else if let Some(base_ot) = &mut self.base_ot {
            self.k0.clear();
            base_ot.recv(&self.s, &mut self.k0);
        }

        self.g0 = Some(
            self.k0.iter()
                .enumerate()
                .map(|(i, key)| {
                    let mut prg = PRG::new(None, i as u64);
                    prg.reseed(key, 0);
                    prg
                })
                .collect(),
        );

        self.delta = Some(bool_to_block(&self.s));
    }

    pub fn setup_recv(&mut self, in_k0: Option<&[[u8; 16]]>, in_k1: Option<&[[u8; 16]]>) {
        self.setup = true;

        if let (Some(in_k0), Some(in_k1)) = (in_k0, in_k1) {
            self.k0.copy_from_slice(in_k0);
            self.k1.copy_from_slice(in_k1);
        } else if let Some(base_ot) = &mut self.base_ot {
            let mut prg = PRG::new(None, 0);
            prg.random_block(&mut self.k0);
            prg.random_block(&mut self.k1);
            base_ot.send(&self.k0, &self.k1);
        }

        self.g0 = Some(
            self.k0.iter()
                .enumerate()
                .map(|(i, key)| {
                    let mut prg = PRG::new(None, i as u64);
                    prg.reseed(key, 0);
                    prg
                })
                .collect(),
        );
        self.g1 = Some(
            self.k1.iter()
                .enumerate()
                .map(|(i, key)| {
                    let mut prg = PRG::new(None, (i + NUM_BITS) as u64);
                    prg.reseed(key, 0);
                    prg
                })
                .collect(),
        );
    }

    pub fn send_pre(&mut self, out: &mut [[u8; 16]], length: usize) {
        if !self.setup {
            self.setup_send(None, None);
        }

        let mut idx = 0;
        while idx + 16 <= length / 128 {
            self.send_pre_block(&mut out[idx * 128..(idx + 16) * 128], 2048);
            idx += 16;
        }

        let remaining = (length / 128- idx) * 128;
        if remaining > 0 {
            let mut temp_out = self.local_out.clone();
            self.send_pre_block(&mut temp_out, remaining);
            out[idx..].copy_from_slice(&temp_out[..remaining]);
        }

        if self.malicious {
            let mut temp_out = self.local_out.clone();
            self.send_pre_block(&mut temp_out, 2 * 128);
        }
    }

    fn send_pre_block(&mut self, out: &mut [[u8; 16]], length: usize) {
        let local_block_size = (length + NUM_BITS - 1) / NUM_BITS * NUM_BITS;
        println!("local_block_size: {}", local_block_size);

        let mut t = vec![[0u8; 16]; BLOCK_SIZE];
        let mut res = vec![[0u8; 16]; BLOCK_SIZE];
        let tmp = if let Some(base_ot) = &mut self.base_ot {
            base_ot.io.receive_data()
        } else {
            vec![[0u8; 16]; BLOCK_SIZE]
        };

        if let Some(prgs) = &mut self.g0 {
            println!("The number of keys is: {}", prgs.len());
            for (i, prg) in prgs.iter_mut().enumerate() {
                let start = i * 2048 / 128;
                let end = start + local_block_size / 128;
                println!("i, start, end: {}, {}, {}", i, start, end);
                prg.random_block(&mut t[start..end]);
                xor_blocks_arr(&mut res[start..end], &t[start..end], &tmp[start..end]);
            }
        }

        transpose(out, &t, NUM_BITS, BLOCK_SIZE);
    }

    pub fn recv_pre(&mut self, out: &mut [[u8; 16]], r: &[bool], length: usize) {
        if !self.setup {
            self.setup_recv(None, None);
        }

        let mut idx = 0;
        let mut block_r = vec![[0u8; 16]; (length + NUM_BITS - 1) / NUM_BITS];

        for (i, chunk) in r.chunks(NUM_BITS).enumerate() {
            block_r[i] = bool_to_block(chunk);
        }

        while idx + 16 <= length / 128 {
            self.recv_pre_block(
                &mut out[(idx * 128)..(idx + 16) * 128], 
                &block_r[idx..idx + 16], 
                2048,
            );
            idx += 16;
        }

        let remaining = (length / 128 - idx) * 128;
        if remaining > 0 {
            let mut temp_out = self.local_out.clone();
            self.recv_pre_block(&mut temp_out, &block_r[idx..], remaining);
            out[idx..].copy_from_slice(&temp_out[..remaining]);
        }

        if self.malicious {
            let mut local_r_block = vec![[0u8; 16]; 2];
            let mut prg = PRG::new(None, 0);
            prg.random_block(&mut local_r_block);
            let mut temp_out = self.local_out.clone();
            self.recv_pre_block(&mut temp_out, &local_r_block, 2 * 128);
        }
    }

    fn recv_pre_block(&mut self, out: &mut [[u8; 16]], r: &[[u8; 16]], length: usize) {
        let mut t = vec![[0u8; 16]; BLOCK_SIZE];
        let mut tmp = vec![[0u8; 16]; BLOCK_SIZE];
        let mut res = vec![[0u8; 16]; BLOCK_SIZE];
        let local_block_size = (length + NUM_BITS - 1) / 128 * 128;

        if let (Some(prgs_g0), Some(prgs_g1)) = (&mut self.g0, &mut self.g1) {
            for (i, (prg0, prg1)) in prgs_g0.iter_mut().zip(prgs_g1.iter_mut()).enumerate() {
                let start = i * BLOCK_SIZE / NUM_BITS;
                let end = start + local_block_size / 128;
                prg0.random_block(&mut t[start..end]);
                prg1.random_block(&mut tmp[start..end]);
                xor_blocks_arr(&mut res[start..end], &t[start..end], &tmp[start..end]);
                xor_blocks_arr(&mut tmp[start..end], &res[start..end], r);
            }
        }

        if let Some(base_ot) = &mut self.base_ot {
            base_ot.io.send_data(&tmp);
        }

        transpose(out, &t, NUM_BITS, BLOCK_SIZE);
    }

    pub fn send_cot(&mut self, data: &mut [[u8; 16]], length: usize) {
        self.send_pre(data, length);

        if self.malicious {
            if !self.send_check(data, length) {
                panic!("OT Extension check failed");
            }
        }
    }

    pub fn recv_cot(&mut self, data: &mut [[u8; 16]], r: &[bool], length: usize) {
        self.recv_pre(data, r, length);

        if self.malicious {
            self.recv_check(data, r, length);
        }
    }

    pub fn send_check(&mut self, out: &[[u8; 16]], length: usize) -> bool {
        let mut seed2 = [0u8; 16];
        let mut x = [0u8; 16];
        let mut t = [[0u8; 16]; 2];
        let mut q = [[0u8; 16]; 2];
        let mut tmp = [[0u8; 16]; 2];
        let mut chi = vec![[0u8; 16]; BLOCK_SIZE];
        q[0] = [0u8; 16];
        q[1] = [0u8; 16];

        if let Some(base_ot) = &mut self.base_ot {
            seed2 = base_ot.io.receive_data()[0];
            base_ot.io.flush();
        }

        let mut chi_prg = PRG::new(Some(&seed2), 0);

        for i in 0..length / BLOCK_SIZE {
            chi_prg.random_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi, &out[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
            xor_blocks(&mut q[0..1], &tmp[0..1]);
        }

        let remain = length % BLOCK_SIZE;
        if remain != 0 {
            chi_prg.random_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi, &out[length - remain..]);
            xor_blocks(&mut q[0..1], &tmp[0..1]);
        }

        // Handle local_out
        chi_prg.random_block(&mut chi);
        vector_inn_prdt_sum_no_red(&mut tmp, &chi, &self.local_out);
        xor_blocks(&mut q[0..1], &tmp[0..1]);

        if let Some(base_ot) = &mut self.base_ot {
            x = base_ot.io.receive_data()[0];
            // Receive t
            let received_data: Vec<[u8; 16]> = base_ot.io.receive_data();
            assert_eq!(received_data.len(), 2, "Expected exactly 2 elements in received data");
            t = [received_data[0], received_data[1]]; // Convert Vec to array
        }

        let delta = self.delta.expect("Delta must be set during setup");
        mul128(&x, &delta, &mut tmp);
        xor_blocks(&mut q[0..1], &tmp);

        cmp_blocks(&q, &t)
    }

    pub fn recv_check(&mut self, out: &[[u8; 16]], r: &[bool], length: usize) {
        let select = [[0u8; 16], [255u8; 16]]; // zero_block and all_one_block
        let mut seed2 = [0u8; 16];
        let mut x = [0u8; 16];
        let mut t = [[0u8; 16]; 2];
        let mut tmp = [[0u8; 16]; 2];
        let mut chi = vec![[0u8; 16]; BLOCK_SIZE];
        t[0] = [0u8; 16];
        t[1] = [0u8; 16];

        let mut prg = PRG::new(None, 0);
        prg.random_block(&mut [seed2]);

        if let Some(base_ot) = &mut self.base_ot {
            base_ot.io.send_data(&[seed2]);
            base_ot.io.flush();
        }

        let mut chi_prg = PRG::new(Some(&seed2), 0);

        for i in 0..length / BLOCK_SIZE {
            chi_prg.random_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi, &out[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
            xor_blocks(&mut t[0..1], &tmp[0..1]);

            for j in 0..BLOCK_SIZE {
                for byt in 0..16 {
                    x[byt] = x[byt] ^ (chi[j][byt] & select[r[i * BLOCK_SIZE + j] as usize][byt]);
                }
            }
        }

        let remain = length % BLOCK_SIZE;
        if remain != 0 {
            chi_prg.random_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi, &out[length - remain..]);
            xor_blocks(&mut t[0..1], &tmp[0..1]);

            for j in 0..remain {
                for byt in 0..16 {
                    x[byt] = x[byt] ^ (chi[j][byt] & select[r[length - remain + 1] as usize][byt]);
                }
            }
        }

        // Handle local_out
        chi_prg.random_block(&mut chi);
        vector_inn_prdt_sum_no_red(&mut tmp, &chi, &self.local_out);
        xor_blocks(&mut t[0..1], &tmp[0..1]);

        for j in 0..256 {
            for byt in 0..16 {
                x[byt] = x[byt] ^ (chi[j][byt] & select[self.local_r[j] as usize][byt]);
            }
        }

        if let Some(base_ot) = &mut self.base_ot {
            base_ot.io.send_data(&[x]);
            base_ot.io.send_data(&t);
        }
    }
}

fn mul128(a: &[u8; 16], b: &[u8; 16], res: &mut [[u8; 16]; 2]) {
    let mut r1 = [0u8; 16];
    let mut r2 = [0u8; 16];

    // Split inputs into low and high 64-bit parts
    let a_low = u64::from_le_bytes(a[0..8].try_into().unwrap());
    let a_high = u64::from_le_bytes(a[8..16].try_into().unwrap());
    let b_low = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let b_high = u64::from_le_bytes(b[8..16].try_into().unwrap());

    // Perform carry-less multiplications
    let tmp3 = clmul64(a_low, b_low); // Low * Low
    let tmp4 = clmul64(a_high, b_low); // High * Low
    let tmp5 = clmul64(a_low, b_high); // Low * High
    let tmp6 = clmul64(a_high, b_high); // High * High

    // Combine results
    let mid = tmp4 ^ tmp5; // XOR intermediate results
    let mid_low = mid & 0xFFFFFFFFFFFFFFFF; // Lower 64 bits shifted to high part of r1
    let mid_high = mid >> 64; // Higher 64 bits shifted to low part of r2

    r1[0..8].copy_from_slice(&((tmp3 & 0xFFFFFFFFFFFFFFFF) as u64).to_le_bytes()); // Low part of tmp3 to r1
    r1[8..16].copy_from_slice(&((tmp3 >> 64 ^ mid_low) as u64).to_le_bytes()); // High part of tmp3 ^ mid_low

    r2[0..8].copy_from_slice(&(((tmp6 ^ mid_high) & 0xFFFFFFFFFFFFFFFF) as u64).to_le_bytes()); // Low part of tmp6 ^ mid_high
    r2[8..16].copy_from_slice(&((tmp6 >> 64) as u64).to_le_bytes()); // High part of tmp6

    res[0] = r1;
    res[1] = r2;
}

// Helper function to perform 64-bit carry-less multiplication
fn clmul64(a: u64, b: u64) -> u128 {
    let mut result = 0u128;
    for i in 0..64 {
        if (b & (1 << i)) != 0 {
            result ^= (a as u128) << i;
        }
    }
    result
}

fn vector_inn_prdt_sum_no_red(res: &mut [[u8; 16]; 2], a: &[[u8; 16]], b: &[[u8; 16]]) {
    // let mut r1 = [0u8; 16]; // Accumulator for first half
    // let mut r2 = [0u8; 16]; // Accumulator for second half
    let mut r1 = [0u8; 16];
    let mut r2 = [0u8; 16];
    let mut r11 = [[0u8; 16]; 2];

    for i in 0..a.len() {
        mul128(&a[i], &b[i], &mut r11); // Perform 128-bit multiplication
        for byt in 0..16 {
            r1[byt] = r1[byt] ^ r11[0][byt];
            r2[byt] = r2[byt] ^ r11[1][byt];
        }
    }

    res[0] = r1;
    res[1] = r2;
}

// Helper functions
fn bool_to_block(bits: &[bool]) -> [u8; 16] {
    let mut block = [0u8; 16];
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            block[i / 8] |= 1 << (i % 8);
        }
    }
    block
}

fn cmp_blocks(a: &[[u8; 16]], b: &[[u8; 16]]) -> bool {
    a == b
}

fn xor_blocks(a: &mut [[u8; 16]], b: &[[u8; 16]]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        for i in 0..16 {
            x[i] ^= y[i];
        }
    }
}

fn and_blocks(a: &mut [[u8; 16]], b: &[[u8; 16]]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        for i in 0..16 {
            x[i] &= y[i];
        }
    }
}

fn xor_blocks_arr(res: &mut [[u8; 16]], x: &[[u8; 16]], y: &[[u8; 16]]) {
    for ((r, a), b) in res.iter_mut().zip(x.iter()).zip(y.iter()) {
        for i in 0..16 {
            r[i] = a[i] ^ b[i];
        }
    }
}

fn transpose(out: &mut [[u8; 16]], t: &[[u8; 16]], num_bits: usize, block_size: usize) {
    println!("Size of out is: {} x {}", out.len(), out[0].len() * 8);
    println!("Size of t is: {} x {}", t.len(), t[0].len() * 8);
    for row in 0..num_bits {
        for col in 0..block_size {
            let idx = row * block_size + col;
            let bit = (t[idx / 128][(idx / 8) % 16] >> (idx % 8)) & 1;
            let new_idx = col * num_bits + row;
            out[new_idx / 128][(new_idx / 8) % 16] |= bit << (new_idx % 8);
        }
    }
}