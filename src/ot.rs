use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::stark_252_prime_field::Stark252PrimeField;
use rand::Rng;
use std::vec::Vec;
use crate::comm_channel::CommunicationChannel;

pub struct OTCO {
    // Base field of STARK-252
    field: Stark252PrimeField,
}

impl OTCO {
    pub fn new() -> Self {
        Self {
            field: Stark252PrimeField::default(),
        }
    }

    pub fn send<IO>(
        &self,
        io: &mut IO,
        data0: &[u8],
        data1: &[u8],
    ) where
        IO: CommunicationChannel,
    {
        let mut rng = rand::thread_rng();

        // Generate a random scalar `a` in the base field
        let a = FieldElement::<Stark252PrimeField>::random(&mut rng);

        // Compute `A = a` (as there are no points, this is scalar-based logic)
        io.send_scalar(&a);

        // Prepare the results for encryption
        let mut encrypted_data = Vec::new();
        for (i, (&d0, &d1)) in data0.iter().zip(data1).enumerate() {
            let b = io.receive_scalar();
            let shared_key = b.pow(a); // b^a as the shared key

            encrypted_data.push((
                d0 ^ shared_key.to_bytes_le()[0],
                d1 ^ shared_key.to_bytes_le()[0],
            ));
        }

        // Send the encrypted data
        io.send_data(&encrypted_data);
    }

    pub fn recv<IO>(
        &self,
        io: &mut IO,
        choices: &[bool],
        output: &mut Vec<u8>,
    ) where
        IO: CommunicationChannel,
    {
        let mut rng = rand::thread_rng();
        let mut private_scalars = Vec::new();

        // Receive scalar `A` from the sender
        let A = io.receive_scalar();

        // Generate `b` values and send them back
        for &choice in choices {
            let b = FieldElement::<Stark252PrimeField>::random(&mut rng);
            private_scalars.push(b);

            // Compute `B = b * (1 + A * choice)`
            let B = if choice {
                b * (A + FieldElement::one())
            } else {
                b
            };
            io.send_scalar(&B);
        }

        // Receive encrypted data
        let received_data = io.receive_data();

        // Decrypt the chosen messages
        for (i, &choice) in choices.iter().enumerate() {
            let shared_key = A.pow(private_scalars[i]); // A^b
            let shared_key_byte = shared_key.to_bytes_le()[0];

            output.push(received_data[i][if choice { 1 } else { 0 }] ^ shared_key_byte);
        }
    }
}
