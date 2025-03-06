zk-SNARK Password Verification

This program demonstrates a simple password verification system as a Proof of Concept for a groth16 zk-SNARK(zero-knowledge succinct non-interactive argument of knowledge). It uses the bellperson library to access groth16 and the bls12-381 elliptic curve to generate and verify a proof without revealing the password itself.

Features:
    A ZKP (Zero Knowledge Proof) that a user knows a password without revealing it
    Uses a zk-SNARK to verify the input password matches the stored password in a secure way
    Passwords are hashed with Blake2b before being used

Requirements:
    Rust(with cargo and rustc)
    bellperson, blake2b_simd, blstrs, and other dependencies from Cargo.toml
    
Follow the official instructions to install Rust: https://www.rust-lang.org/learn/get-started

To use:
    - Clone the repository
    - Build the project (cargo build)
    - Run the program (cargo run)
    
You will then be prompted to enter a password. The program will check if your input matches the stored password (which is "password")

How it Works:
    The program uses password hashing based off the Blake2b hash function to hash both input and stored passwords

The hashed passwords are then used in a zk-Snark circuit to prove that the user knows the correct password
    This circuit is generated using the groth16 zk-SNARK protocol from the bellperson crate

The program generated a zk-SNARK using the groth16 proving system. this allows for verification of the password without sharing the private values.

The circuit is verified against the proof and the program completes.
