//! This tool generates verification key for an ELF file with sp1_sdk
//! cargo run --bin canoe-sp1-cc-vkey-bin --release -- --elf <path>
use alloy_primitives::B256;
use clap::Parser;
use sp1_sdk::{HashableKey, ProverClient};

use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(about = "Generate verification key for an ELF file with sp1_sdk")]
struct Cli {
    /// Path to the ELF file
    #[arg(long)]
    elf: Option<PathBuf>,

    /// Print the verification key as a simple hex string
    #[arg(long)]
    hex: bool,
}

fn u32_to_u8(limbs: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let be_bytes = limb.to_be_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&be_bytes);
    }
    bytes
}

fn main() {
    let cli = Cli::parse();

    let canoe_client_elf: Vec<u8> = if let Some(elf_path) = cli.elf {
        fs::read(&elf_path).expect("Failed to read ELF file")
    } else {
        canoe_sp1_cc_host::ELF.to_vec()
    };

    let client = ProverClient::from_env();

    // from succinct lab, the vkey stays the same for all major release version
    // regardless minor changes. For example, 5.2.1 and 5.0.8 produce identical vkey
    // for the same ELF.
    let (_pk, canoe_vk) = client.setup(&canoe_client_elf);
    let limbs = canoe_vk.vk.hash_u32();

    if cli.hex {
        println!("{}", B256::from(u32_to_u8(&limbs)));
    } else {
        println!("canoe sp1cc v_key {:?}", &limbs);
    }
}
