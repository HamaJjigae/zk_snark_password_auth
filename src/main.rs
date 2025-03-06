use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use blake2b_simd::Params;
use blstrs::Scalar;
use ff::Field;
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::io;

// we derive clone here cuz its not necessary to reconstruct twice for bellperson
#[derive(Clone)]
struct PasswordCirc {
    pub password: Option<Scalar>,
    pub stored_password: Scalar,
}

impl Circuit<Scalar> for PasswordCirc {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        //sets password var into the R1CS
        let password = cs.alloc(
            || "password",
            || self.password.ok_or(SynthesisError::AssignmentMissing),
        )?;
        //sets stored_password as var into R1CS
        let stored_password = cs.alloc_input(|| "stored_password", || Ok(self.stored_password))?;

        // very simple a b = c here for password validation. but is a nice PoC
        cs.enforce(
            || "password validation",
            |lc| lc + password,
            |lc| lc + CS::one(),
            |lc| lc + stored_password,
        );

        Ok(())
    }
}

fn main() {
    let stored_pass = "password";
    let sp_scalar = to_scalar(stored_pass);

    println!("Enter your password: ");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read");
    let input = input.trim();
    let ip_scalar = to_scalar(input);

    //initialize our Circ from the struct. unwraping the Option
    let circuit = PasswordCirc {
        password: Some(ip_scalar),
        stored_password: sp_scalar,
    };

    //pretty standard Osbased rng value
    let rng = &mut OsRng;
    let params =
        //this match is using random params from bls12_381 and our circuit for synthesis
        match bellperson::groth16::generate_random_parameters::<blstrs::Bls12, PasswordCirc, _>(
            circuit.clone(),
            rng,
        ) {
            Ok(params) => params,
            Err(e) => {
                eprintln!("Failed to generate params: {:?}", e);
                return;
            }
        };

    //this creates our verification key off of the params previously created
    let pvk = bellperson::groth16::prepare_verifying_key(&params.vk);

    //this creates our 'random' proof off of all the previous variables
    let proof = match bellperson::groth16::create_random_proof(circuit, &params, rng) {
        Ok(proof) => proof,
        Err(e) => {
            eprintln!("Failed to create proof: {:?}", e);
            return;
        }
    };

    //finally we verify the proof and match the possible outputs with the public inputs (sp_scalar)
    match bellperson::groth16::verify_proof(&pvk, &proof, &[sp_scalar]) {
        Ok(true) => println!("Proof is valid!"),
        Ok(false) => println!("Proof is invalid!"),
        Err(e) => println!("Verification failed with error: {:?}", e),
    }
}

fn to_scalar(input: &str) -> Scalar {
    // hashing the input to produce a fixed-length digest (using blake2b)
    let hash = Params::new().hash(input.as_bytes());
    //turn the hash into bytes
    let hash_bytes = hash.as_bytes();
    //taking the first 32 bytes of a hash to make the seed for ChaCha
    //bls12_381 is a 48-byte field but 32 is used for ChaChaRng Seed
    let mut seed = [0u8; 32];
    // copy the first 32 bytes to the seed
    seed.copy_from_slice(&hash_bytes[..32]);
    let mut rng = ChaChaRng::from_seed(seed);
    //makes a random Scalar within the valid range of BLS12_381 using ChaCha
    //This ensures non-determinism while also being within the modulus
    let scalar = Scalar::random(&mut rng);

    scalar
}
