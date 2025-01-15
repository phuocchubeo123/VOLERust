extern crate lambdaworks_math;
extern crate rand;

use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use lambdaworks_math::traits::ByteConversion;
use rand::random;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub fn rand_field_element() -> FE {
    let rand_big = UnsignedInteger { limbs: random() };
    FE::new(rand_big)
}

fn main() {
        // Create a sample FieldElement
    let original_value = rand_field_element();

    // Serialize the FieldElement to little-endian bytes
    let serialized_bytes = original_value.to_bytes_le();
    println!("Serialized bytes: {:?}", serialized_bytes);
    println!("Serialized size: {}", serialized_bytes.len());

    // Deserialize back to a FieldElement
    match FE::from_bytes_le(&serialized_bytes) {
        Ok(deserialized_value) => {
            println!("Deserialized value: {}", deserialized_value);

            // Check if the deserialized value matches the original
            if deserialized_value == original_value {
                println!("Success: Deserialized value matches the original!");
            } else {
                println!(
                    "Error: Deserialized value does not match the original. Original: {}, Deserialized: {}",
                    original_value, deserialized_value
                );
            }
        }
        Err(e) => {
            println!("Error: Failed to deserialize bytes. {:?}", e);
        }
    }
}
