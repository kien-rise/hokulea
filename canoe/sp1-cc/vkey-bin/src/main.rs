//! This tool generates verification key for an ELF file with sp1_sdk
//! cargo run --bin canoe-sp1-cc-vkey-bin --release
use canoe_sp1_cc_verifier::CanoeSp1CCVerifier;
use sp1_sdk::{HashableKey, ProverClient};
use std::fs;

fn main() {
    let canoe_client_elf: Vec<u8> = if let Ok(elf_path) = std::env::var("CANOE_CLIENT_ELF") {
        fs::read(&elf_path).expect(&format!("Failed to read ELF file from: {}", elf_path))
    } else {
        canoe_sp1_cc_host::DEFAULT_ELF.to_vec()
    };

    let client = ProverClient::from_env();

    // from succinct lab, the vkey stays the same for all major release version
    // regardless minor changes. For example, 5.2.1 and 5.0.8 produce identical vkey
    // for the same ELF.
    let (_pk, canoe_vk) = client.setup(&canoe_client_elf);
    let limbs = canoe_vk.vk.hash_u32();

    println!("canoe sp1cc v_key {:?}", &limbs);
    println!("encoded as {:?}", CanoeSp1CCVerifier::encode_vkey(&limbs));
}
