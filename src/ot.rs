use crate::hash::Hash;
use crate::comm_channel::CommunicationChannel;
use p256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use p256::elliptic_curve::{Field, Group}; 
use p256::{PublicKey, Scalar, AffinePoint, ProjectivePoint};
use p256::ecdh::EphemeralSecret;
use rand::Rng;
use std::ops::Mul;

pub struct OTCO<IO> {
    io: IO,
}

impl<IO: CommunicationChannel> OTCO<IO> {
    pub fn new(io: IO) -> Self {
        Self { io }
    }

    /// Sender's OT implementation
    pub fn send(&mut self, data0: &[[u8; 16]], data1: &[[u8; 16]]) {
        let length = data0.len();
        let mut rng = rand::thread_rng();

        // Generate random scalar `a`
        let a = Scalar::random(&mut rng);

        // Compute A = G * a (G is the generator of the curve)
        let A = ProjectivePoint::generator() * a;
        let A_affine = AffinePoint::from(A);

        // Send A to the receiver
        let A_encoded = A_affine.to_encoded_point(false);
        self.io.send_point(&A_encoded);

        // Compute (A * a)^-1
        let mut A_a_inverse = A * a;
        A_a_inverse = A_a_inverse.neg();

        let mut B_points = vec![ProjectivePoint::identity(); length];
        let mut BA_points = vec![ProjectivePoint::identity(); length];

        // Receive B points and compute BA points
        for i in 0..length {
            let b_point = self.io.receive_point();
            let b_affine = AffinePoint::from_encoded_point(&b_point)
                .expect("Failed to decode AffinePoint from EncodedPoint");
            let B_projective = ProjectivePoint::from(b_affine);

            // Compute B[i] * a
            let B_a = B_projective * a;
            B_points[i] = B_a;

            // Compute BA[i] = B[i] + (A * a)^-1
            BA_points[i] = B_a + A_a_inverse;
        }

        self.io.flush();

        // Encrypt and send the data
        for i in 0..length {
            let key_b = Hash::kdf(
                &B_points[i].to_affine().to_encoded_point(false).as_bytes(),
                i as u64,
            );
            let key_ba = Hash::kdf(
                &BA_points[i].to_affine().to_encoded_point(false).as_bytes(),
                i as u64,
            );

            let encrypted0 = xor_blocks(&data0[i], &key_b);
            let encrypted1 = xor_blocks(&data1[i], &key_ba);

            self.io.send_data(&[encrypted0, encrypted1]);
        }
    }

    /// Receiver's OT implementation
    pub fn recv(&mut self, choices: &[bool], output: &mut Vec<[u8; 16]>) {
        let length = choices.len();
        let mut rng = rand::thread_rng();

        // Generate random scalars `b`
        let b_scalars: Vec<Scalar> = (0..length).map(|_| Scalar::random(&mut rng)).collect();

        let A_encoded = self.io.receive_point();
        let A_affine = AffinePoint::from_encoded_point(&A_encoded)
            .expect("Invalid A point received");
        let A_projective = ProjectivePoint::from(A_affine);

        // Compute and send B points
        for (i, &choice) in choices.iter().enumerate() {
            let mut B_projective = ProjectivePoint::generator() * b_scalars[i];

            // If the choice is true, add A to B[i]
            if choice {
                B_projective += A_projective;
            }

            let B_encoded = B_projective.to_affine().to_encoded_point(false);
            self.io.send_point(&B_encoded);

        }

        self.io.flush();

        // Compute shared points and decrypt data
        for i in 0..length {
            let B_a = A_projective * b_scalars[i];
            let key_as = Hash::kdf(
                &B_a.to_affine().to_encoded_point(false).as_bytes(),
                i as u64,
            );

            let encrypted = self.io.receive_data();
            output.push(if choices[i] {
                xor_blocks(&encrypted[1], &key_as)
            } else {
                xor_blocks(&encrypted[0], &key_as)
            });
        }
    }
}

/// XOR two 128-bit blocks
fn xor_blocks(block1: &[u8; 16], block2: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = block1[i] ^ block2[i];
    }
    result
}
