use crate::iknp::IKNP;
use crate::prg::PRG;
use crate::comm_channel::CommunicationChannel;
use crate::preot::OTPre;

pub struct BaseCot<'a, IO: CommunicationChannel> {
    party: u8, // Alice: 0, Bob: 1
    one: [u8; 16],
    minus_one: [u8; 16],
    ot_delta: Option<[u8; 16]>,
    iknp: IKNP<'a, IO>,
    malicious: bool,
}

impl<'a, IO: CommunicationChannel> BaseCot<'a, IO> {
    pub fn new(party: u8, io: &'a mut IO, malicious: bool) -> Self {
        let one = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // Little-endian representation of 1
        let minus_one = [
            254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ]; // Little-endian representation of u128::MAX - 1

        BaseCot {
            party,
            one,
            minus_one,
            ot_delta: None,
            iknp: IKNP::new(io, malicious),
            malicious,
        }
    }

    pub fn cot_gen_pre(&mut self, deltain: Option<[u8; 16]>) {
        if let Some(deltain) = deltain {
            if self.party == 0 {
                self.ot_delta = Some(deltain);
                let delta_bool = block_to_bool(&deltain);
                self.iknp.setup_send(Some(&delta_bool), None);
            } else {
                self.iknp.setup_recv(None, None);
            }
        } else {
            if self.party == 0 {
                let mut prg = PRG::new(None, 0);
                let mut tmp = [[0u8; 16]];
                prg.random_block(&mut tmp);
                let mut delta = tmp[0];
                delta = bitwise_and(&delta, &self.minus_one);
                delta = bitwise_xor(&delta, &self.one);
                self.ot_delta = Some(delta);
                let delta_bool = block_to_bool(&delta);
                self.iknp.setup_send(Some(&delta_bool), None);
            } else {
                self.iknp.setup_recv(None, None);
            }
        }
    }

    pub fn cot_gen(&mut self, ot_data: &mut [[u8; 16]], size: usize, pre_bool: Option<&[bool]>) {
        if self.party == 0 {
            self.iknp.send_cot(ot_data, size);
            self.iknp.base_ot.io.flush();
            for block in ot_data.iter_mut() {
                *block = bitwise_and(block, &self.minus_one);
            }
        } else {
            let mut prg = PRG::new(None, 0);
            let mut pre_bool_ini = vec![false; size];
            if let Some(pre_bool) = pre_bool {
                if !self.malicious {
                    pre_bool_ini.copy_from_slice(pre_bool);
                }
            } else {
                prg.random_bool_array(&mut pre_bool_ini);
            }

            self.iknp.recv_cot(ot_data, &pre_bool_ini, size);

            let ch = [[0u8; 16]; 2].map(|mut b| {
                b[15] = 1;
                b
            });
            for (i, block) in ot_data.iter_mut().enumerate() {
                *block = bitwise_xor(&bitwise_and(block, &self.minus_one), &ch[pre_bool_ini[i] as usize]);
            }
        }
    }

    pub fn cot_gen_preot(&mut self, pre_ot: &mut OTPre, size: usize, pre_bool: Option<&[bool]>) {
        let mut ot_data = vec![[0u8; 16]; size]; // Allocate space for `ot_data`

        if self.party == 0 {
            // ALICE
            self.iknp.send_cot(&mut ot_data, size);
            self.iknp.base_ot.io.flush();

            // Apply `minus_one` to all blocks
            for block in ot_data.iter_mut() {
                *block = bitwise_and(block, &self.minus_one);
            }

            // Call `send_pre` on `pre_ot`
            if let Some(delta) = self.ot_delta {
                pre_ot.send_pre(&ot_data, delta);
            }
        } else {
            // BOB
            let mut prg = PRG::new(None, 0);
            let mut pre_bool_ini = vec![false; size];

            // Initialize `pre_bool_ini`
            if let Some(pre_bool) = pre_bool {
                if !self.malicious {
                    pre_bool_ini.copy_from_slice(pre_bool);
                }
            } else {
                prg.random_bool_array(&mut pre_bool_ini);
            }

            // Call `recv_cot` on `iknp`
            self.iknp.recv_cot(&mut ot_data, &pre_bool_ini, size);

            let mut ch = [[0u8; 16]; 2];
            ch[0] = [0u8; 16]; // Equivalent to `zero_block`
            ch[1][0] = 1;     // Equivalent to `makeBlock(0, 1)`

            // Modify `ot_data` based on `pre_bool_ini`
            for (i, block) in ot_data.iter_mut().enumerate() {
                *block = bitwise_xor(&bitwise_and(block, &self.minus_one), &ch[pre_bool_ini[i] as usize]);
            }

            // Call `recv_pre` on `pre_ot`
            pre_ot.recv_pre(&ot_data, Some(&pre_bool_ini));
        }
    }

    // Debugging check for COT
    pub fn check_cot(&mut self, data: &[[u8; 16]], len: usize) -> bool {
        if self.party == 0 {
            if let Some(delta) = self.ot_delta {
                self.iknp.base_ot.io.send_data(&[delta]);
            }
            self.iknp.base_ot.io.send_data(data);
            self.iknp.base_ot.io.flush();
            true
        } else {
            let mut tmp = vec![[0u8; 16]; len];
            let mut ch = [[0u8; 16]; 2];
            ch[1] = self.iknp.base_ot.io.receive_data()[0];
            ch[0] = [0u8; 16];
            tmp = self.iknp.base_ot.io.receive_data();
            for i in 0..len {
                tmp[i] = bitwise_xor(&tmp[i], &ch[get_lsb(&data[i]) as usize]);
            }
            cmp_blocks(&tmp, data)
        }
    }
}

fn block_to_bool(block: &[u8; 16]) -> [bool; 128] {
    let mut result = [false; 128];
    for (i, byte) in block.iter().enumerate() {
        for bit in 0..8 {
            result[i * 8 + bit] = (byte >> bit) & 1 != 0;
        }
    }
    result
}

fn get_lsb(block: &[u8; 16]) -> bool {
    block[0] & 1 != 0
}

fn cmp_blocks(a: &[[u8; 16]], b: &[[u8; 16]]) -> bool {
    a == b
}

fn bitwise_xor(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    [
        a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3],
        a[4] ^ b[4], a[5] ^ b[5], a[6] ^ b[6], a[7] ^ b[7],
        a[8] ^ b[8], a[9] ^ b[9], a[10] ^ b[10], a[11] ^ b[11],
        a[12] ^ b[12], a[13] ^ b[13], a[14] ^ b[14], a[15] ^ b[15],
    ]
}

fn bitwise_and(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    [
        a[0] & b[0], a[1] & b[1], a[2] & b[2], a[3] & b[3],
        a[4] & b[4], a[5] & b[5], a[6] & b[6], a[7] & b[7],
        a[8] & b[8], a[9] & b[9], a[10] & b[10], a[11] & b[11],
        a[12] & b[12], a[13] & b[13], a[14] & b[14], a[15] & b[15],
    ]
}
