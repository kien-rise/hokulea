use alloy_primitives::Address;
use alloy_rpc_types::BlockNumberOrTag;
use alloy_serde::OtherFields;
use alloy_sol_types::{sol_data::Bool, SolType};
use alloy_genesis::ChainConfig;
use anyhow::Result;
use async_trait::async_trait;
use canoe_bindings::StatusCode;
use canoe_provider::{CanoeInput, CanoeProvider, CertVerifierCall};
use rsp_primitives::genesis::genesis_from_json;
use sp1_cc_client_executor::ContractInput;
use sp1_cc_host_executor::{EvmSketch, Genesis};
use sp1_sdk::{
    network::FulfillmentStrategy, Prover, ProverClient, SP1Proof, SP1ProofMode,
    SP1ProofWithPublicValues, SP1Stdin, SP1_CIRCUIT_VERSION,
};
use std::{
    env,
    time::{Duration, Instant},
};
use tracing::{info, warn};
use url::Url;

/// The ELF we want to execute inside the zkVM.
pub const ELF: &[u8] = include_bytes!("../../elf/canoe-sp1-cc-client");

const DEFAULT_NETWORK_PRIVATE_KEY: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000001";
const SP1_CC_PROOF_STRATEGY_ENV: &str = "SP1_CC_PROOF_STRATEGY";

/// Get the fulfillment strategy from the environment variable
fn env_fulfillment_strategy(var_name: &str) -> FulfillmentStrategy {
    match env::var(var_name) {
        Ok(value) => {
            let value_lower = value.to_ascii_lowercase();
            match value_lower.as_str() {
                "hosted" => FulfillmentStrategy::Hosted,
                "reserved" => FulfillmentStrategy::Reserved,
                _ => {
                    warn!(
                        "Unknown `{}` value `{}`; defaulting to reserved fulfillment strategy",
                        var_name, value_lower
                    );
                    FulfillmentStrategy::Reserved
                }
            }
        }
        Err(_) => FulfillmentStrategy::Reserved,
    }
}

pub const KURTOSIS_DEVNET_GENESIS: &str = include_str!("./kurtosis_devnet_genesis.json");
pub const HOLESKY_GENESIS: &str = include_str!("./holesky_genesis.json");
/// A canoe provider implementation with Sp1 contract call
/// CanoeSp1CCProvider produces the receipt of type SP1ProofWithPublicValues,
/// SP1ProofWithPublicValues contains a Stark proof which can be verified in
/// native program using sp1-sdk. However, if you requires Stark verification
/// within zkVM, please use [CanoeSp1CCReducedProofProvider]
#[derive(Debug, Clone)]
pub struct CanoeSp1CCProvider {
    /// rpc to l1 geth node
    pub eth_rpc_url: Url,
    /// if true, execute and return a mock proof
    pub mock_mode: bool,
    pub custom_chain_config: Option<ChainConfig>,
}

#[async_trait]
impl CanoeProvider for CanoeSp1CCProvider {
    type Receipt = sp1_sdk::SP1ProofWithPublicValues;

    async fn create_certs_validity_proof(
        &self,
        canoe_inputs: Vec<CanoeInput>,
    ) -> Option<Result<Self::Receipt>> {
        // if there is nothing to prove against return early
        if canoe_inputs.is_empty() {
            return None;
        }

        Some(
            get_sp1_cc_proof(
                canoe_inputs,
                self.eth_rpc_url.clone(),
                self.mock_mode,
                self.custom_chain_config.clone(),
            )
            .await,
        )
    }
}

/// A canoe provider implementation with Sp1 contract call
/// The receipt only contains the stark proof from the SP1ProofWithPublicValues, which is produced
/// by the implementation CanoeSp1CCProvider.
/// CanoeSp1CCReducedProofProvider is needs when the proof verification takes place within
/// zkVM. If you don't require verification within zkVM, please consider using [CanoeSp1CCProvider].
#[derive(Debug, Clone)]
pub struct CanoeSp1CCReducedProofProvider {
    /// rpc to l1 geth node
    pub eth_rpc_url: Url,
    /// if true, execute and return a mock proof
    pub mock_mode: bool,
    pub custom_chain_config: Option<ChainConfig>,
}

#[async_trait]
impl CanoeProvider for CanoeSp1CCReducedProofProvider {
    type Receipt = sp1_core_executor::SP1ReduceProof<sp1_prover::InnerSC>;

    async fn create_certs_validity_proof(
        &self,
        canoe_inputs: Vec<CanoeInput>,
    ) -> Option<Result<Self::Receipt>> {
        // if there is nothing to prove against return early
        if canoe_inputs.is_empty() {
            return None;
        }

        match get_sp1_cc_proof(
            canoe_inputs,
            self.eth_rpc_url.clone(),
            self.mock_mode,
            self.custom_chain_config.clone(),
        )
        .await
        {
            Ok(proof) => {
                let SP1Proof::Compressed(proof) = proof.proof else {
                    panic!("cannot get Sp1ReducedProof")
                };
                Some(Ok(*proof))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

async fn get_sp1_cc_proof(
    canoe_inputs: Vec<CanoeInput>,
    eth_rpc_url: Url,
    mock_mode: bool,
    custom_chain_config: Option<ChainConfig>,
) -> Result<sp1_sdk::SP1ProofWithPublicValues> {
    // ensure chain id and l1 block number across all DAcerts are identical
    let l1_chain_id = canoe_inputs[0].l1_chain_id;

    let l1_head_block_number = canoe_inputs[0].l1_head_block_number;
    for canoe_input in canoe_inputs.iter() {
        assert!(canoe_input.l1_chain_id == l1_chain_id);
        assert!(canoe_input.l1_head_block_number == l1_head_block_number);
    }
    let start = Instant::now();
    info!(
        "begin to generate a sp1-cc proof for {} number of altda commitment at l1 block number {} with chainID {}",
        canoe_inputs.len(),
        l1_head_block_number,
        l1_chain_id,
    );

    // Which block VerifyDACert eth-calls are executed against.
    let block_number = BlockNumberOrTag::Number(l1_head_block_number);

    let genesis = if let Some(chain_config) = custom_chain_config {
        Genesis::Custom(chain_config)
    } else if let Ok(genesis) = Genesis::try_from(l1_chain_id) {
        genesis
    } else {
        let chain_config = match l1_chain_id {
            17000 => genesis_from_json(HOLESKY_GENESIS).expect("genesis from json"),
            3151908 => genesis_from_json(KURTOSIS_DEVNET_GENESIS).expect("genesis from json"),
            _ => panic!("chain id {l1_chain_id} is not supported by canoe sp1 cc"),
        };
        Genesis::Custom(chain_config.config)
    };

    let sketch = EvmSketch::builder()
        .at_block(block_number)
        .with_genesis(genesis)
        .el_rpc_url(eth_rpc_url)
        .build()
        .await?;

    // pre populate the state
    for canoe_input in canoe_inputs.iter() {
        match CertVerifierCall::build(&canoe_input.altda_commitment) {
            CertVerifierCall::LegacyV2Interface(call) => {
                let contract_input =
                    ContractInput::new_call(canoe_input.verifier_address, Address::default(), call);
                let returns_bytes = sketch
                    .call_raw(&contract_input)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

                let is_valid = Bool::abi_decode(&returns_bytes).expect("deserialize returns_bytes");
                if is_valid != canoe_input.claimed_validity {
                    panic!("in the host executor part, executor arrives to a different answer than the claimed answer. Something inconsistent in the view of eigenda-proxy and zkVM");
                }
            }
            CertVerifierCall::ABIEncodeInterface(call) => {
                let contract_input =
                    ContractInput::new_call(canoe_input.verifier_address, Address::default(), call);
                let returns_bytes = sketch
                    .call_raw(&contract_input)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

                let returns = <StatusCode as SolType>::abi_decode(&returns_bytes)
                    .expect("deserialize returns_bytes");
                let is_valid = returns == StatusCode::SUCCESS;
                if is_valid != canoe_input.claimed_validity {
                    panic!("in the host executor part, executor arrives to a different answer than the claimed answer. Something inconsistent in the view of eigenda-proxy and zkVM");
                }
            }
        };
    }

    let evm_state_sketch = sketch
        .finalize()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Feed the sketch into the client.
    let input_bytes = bincode::serialize(&evm_state_sketch)
        .expect("bincode should have serialized the EVM sketch");

    // Assert that deserialization works and produces the same data
    match bincode::deserialize::<sp1_cc_client_executor::io::EvmSketchInput>(&input_bytes) {
        Ok(deserialized) => {
            // Compare each field individually to identify differences
            if deserialized.anchor != evm_state_sketch.anchor {
                panic!("Field 'anchor' differs after serialization/deserialization");
            }
            if deserialized.genesis != evm_state_sketch.genesis {
                panic!("Field 'genesis' differs after serialization/deserialization");
            }
            if deserialized.ancestor_headers != evm_state_sketch.ancestor_headers {
                panic!("Field 'ancestor_headers' differs after serialization/deserialization");
            }
            if deserialized.state != evm_state_sketch.state {
                panic!("Field 'state' differs after serialization/deserialization");
            }
            if deserialized.bytecodes != evm_state_sketch.bytecodes {
                panic!("Field 'bytecodes' differs after serialization/deserialization");
            }
            if deserialized.receipts != evm_state_sketch.receipts {
                panic!("Field 'receipts' differs after serialization/deserialization");
            }
            info!("✅ Serialization/deserialization roundtrip successful for all 6 fields");
        }
        Err(e) => {
            // Test individual field serialization to identify the problematic field
            info!("Testing individual field serialization...");

            // Test anchor field
            match bincode::serialize(&evm_state_sketch.anchor) {
                Ok(anchor_bytes) => {
                    match bincode::deserialize(&anchor_bytes) {
                        Ok(deserialized_anchor) => {
                            if evm_state_sketch.anchor == deserialized_anchor {
                                info!("✅ Field 'anchor' serialization OK");
                            } else {
                                panic!("❌ Field 'anchor' differs after round-trip");
                            }
                        }
                        Err(anchor_err) => panic!("❌ Field 'anchor' deserialization failed: {:?}", anchor_err),
                    }
                }
                Err(anchor_err) => panic!("❌ Field 'anchor' serialization failed: {:?}", anchor_err),
            }

            // Test genesis field - focus on Genesis::Custom ChainConfig fields
            match &evm_state_sketch.genesis {
                sp1_cc_host_executor::Genesis::Custom(chain_config) => {
                    info!("Testing Genesis::Custom with ChainConfig fields...");
                    
                    // Test individual ChainConfig fields
                    info!("Testing chain_id: {}", chain_config.chain_id);
                    match bincode::serialize(&chain_config.chain_id) {
                        Ok(bytes) => match bincode::deserialize::<u64>(&bytes) {
                            Ok(val) => info!("✅ chain_id OK: {}", val),
                            Err(e) => panic!("❌ chain_id deserialize failed: {:?}", e),
                        },
                        Err(e) => panic!("❌ chain_id serialize failed: {:?}", e),
                    }
                    
                    info!("Testing extra_fields with {} entries", chain_config.extra_fields.len());
                    match bincode::serialize(&chain_config.extra_fields) {
                        Ok(bytes) => match bincode::deserialize::<OtherFields>(&bytes) {
                            Ok(_) => info!("✅ extra_fields OK"),
                            Err(e) => panic!("❌ extra_fields deserialize failed: {:?}", e),
                        },
                        Err(e) => panic!("❌ extra_fields serialize failed: {:?}", e),
                    }
                    
                    // Test each ChainConfig field individually
                    info!("Testing all ChainConfig fields individually...");
                    
                    macro_rules! test_field {
                        ($field:expr, $field_name:expr) => {
                            match bincode::serialize(&$field) {
                                Ok(bytes) => {
                                    info!("✅ {} serialize OK ({} bytes)", $field_name, bytes.len());
                                }
                                Err(e) => panic!("❌ {} serialize failed: {:?}", $field_name, e),
                            }
                        };
                    }
                    
                    test_field!(chain_config.homestead_block, "homestead_block");
                    test_field!(chain_config.dao_fork_block, "dao_fork_block");
                    test_field!(chain_config.dao_fork_support, "dao_fork_support");
                    test_field!(chain_config.eip150_block, "eip150_block");
                    test_field!(chain_config.eip155_block, "eip155_block");
                    test_field!(chain_config.eip158_block, "eip158_block");
                    test_field!(chain_config.byzantium_block, "byzantium_block");
                    test_field!(chain_config.constantinople_block, "constantinople_block");
                    test_field!(chain_config.petersburg_block, "petersburg_block");
                    test_field!(chain_config.istanbul_block, "istanbul_block");
                    test_field!(chain_config.muir_glacier_block, "muir_glacier_block");
                    test_field!(chain_config.berlin_block, "berlin_block");
                    test_field!(chain_config.london_block, "london_block");
                    test_field!(chain_config.arrow_glacier_block, "arrow_glacier_block");
                    test_field!(chain_config.gray_glacier_block, "gray_glacier_block");
                    test_field!(chain_config.merge_netsplit_block, "merge_netsplit_block");
                    test_field!(chain_config.shanghai_time, "shanghai_time");
                    test_field!(chain_config.cancun_time, "cancun_time");
                    test_field!(chain_config.prague_time, "prague_time");
                    test_field!(chain_config.osaka_time, "osaka_time");
                    test_field!(chain_config.terminal_total_difficulty, "terminal_total_difficulty");
                    test_field!(chain_config.terminal_total_difficulty_passed, "terminal_total_difficulty_passed");
                    test_field!(chain_config.ethash, "ethash");
                    test_field!(chain_config.clique, "clique");
                    test_field!(chain_config.parlia, "parlia");
                    test_field!(chain_config.deposit_contract_address, "deposit_contract_address");
                    test_field!(chain_config.blob_schedule, "blob_schedule");
                    test_field!(chain_config.bpo1_time, "bpo1_time");
                    test_field!(chain_config.bpo2_time, "bpo2_time");
                    test_field!(chain_config.bpo3_time, "bpo3_time");
                    test_field!(chain_config.bpo4_time, "bpo4_time");
                    test_field!(chain_config.bpo5_time, "bpo5_time");
                    
                    // Test extra_fields in detail
                    info!("Testing extra_fields in detail: {} entries", chain_config.extra_fields.len());
                    for (key, value) in &chain_config.extra_fields {
                        info!("  extra_field[{}] = {:?}", key, value);
                        match bincode::serialize(value) {
                            Ok(_) => info!("    ✅ extra_field[{}] serialize OK", key),
                            Err(e) => panic!("    ❌ extra_field[{}] serialize failed: {:?}", key, e),
                        }
                    }
                    
                    info!("All individual fields tested, now testing full ChainConfig...");
                    match bincode::serialize(chain_config) {
                        Ok(bytes) => {
                            info!("ChainConfig serialized to {} bytes", bytes.len());
                            match bincode::deserialize::<alloy_genesis::ChainConfig>(&bytes) {
                                Ok(_) => info!("✅ ChainConfig roundtrip OK"),
                                Err(e) => panic!("❌ ChainConfig deserialize failed: {:?}", e),
                            }
                        },
                        Err(e) => panic!("❌ ChainConfig serialize failed: {:?}", e),
                    }
                    
                    // Finally test the full Genesis enum
                    match bincode::serialize(&evm_state_sketch.genesis) {
                        Ok(genesis_bytes) => {
                            match bincode::deserialize::<sp1_cc_host_executor::Genesis>(&genesis_bytes) {
                                Ok(deserialized_genesis) => {
                                    if evm_state_sketch.genesis == deserialized_genesis {
                                        info!("✅ Full Genesis serialization OK");
                                    } else {
                                        panic!("❌ Full Genesis differs after round-trip");
                                    }
                                }
                                Err(genesis_err) => panic!("❌ Full Genesis deserialization failed: {:?}", genesis_err),
                            }
                        }
                        Err(genesis_err) => panic!("❌ Full Genesis serialization failed: {:?}", genesis_err),
                    }
                }
                other => {
                    info!("Genesis variant: {:?}", other);
                    match bincode::serialize(&evm_state_sketch.genesis) {
                        Ok(genesis_bytes) => {
                            match bincode::deserialize::<sp1_cc_host_executor::Genesis>(&genesis_bytes) {
                                Ok(deserialized_genesis) => {
                                    if evm_state_sketch.genesis == deserialized_genesis {
                                        info!("✅ Non-Custom Genesis serialization OK");
                                    } else {
                                        panic!("❌ Non-Custom Genesis differs after round-trip");
                                    }
                                }
                                Err(genesis_err) => panic!("❌ Non-Custom Genesis deserialization failed: {:?}", genesis_err),
                            }
                        }
                        Err(genesis_err) => panic!("❌ Non-Custom Genesis serialization failed: {:?}", genesis_err),
                    }
                }
            }

            // // Test ancestor_headers field
            // match bincode::serialize(&evm_state_sketch.ancestor_headers) {
            //     Ok(headers_bytes) => {
            //         match bincode::deserialize::<_>(&headers_bytes) {
            //             Ok(deserialized_headers) => {
            //                 if evm_state_sketch.ancestor_headers == deserialized_headers {
            //                     info!("✅ Field 'ancestor_headers' serialization OK");
            //                 } else {
            //                     panic!("❌ Field 'ancestor_headers' differs after round-trip");
            //                 }
            //             }
            //             Err(headers_err) => panic!("❌ Field 'ancestor_headers' deserialization failed: {:?}", headers_err),
            //         }
            //     }
            //     Err(headers_err) => panic!("❌ Field 'ancestor_headers' serialization failed: {:?}", headers_err),
            // }

            // Test state field
            match bincode::serialize(&evm_state_sketch.state) {
                Ok(state_bytes) => {
                    match bincode::deserialize::<_>(&state_bytes) {
                        Ok(deserialized_state) => {
                            if evm_state_sketch.state == deserialized_state {
                                info!("✅ Field 'state' serialization OK");
                            } else {
                                panic!("❌ Field 'state' differs after round-trip");
                            }
                        }
                        Err(state_err) => panic!("❌ Field 'state' deserialization failed: {:?}", state_err),
                    }
                }
                Err(state_err) => panic!("❌ Field 'state' serialization failed: {:?}", state_err),
            }

            // // Test bytecodes field
            // match bincode::serialize(&evm_state_sketch.bytecodes) {
            //     Ok(bytecodes_bytes) => {
            //         match bincode::deserialize::<_>(&bytecodes_bytes) {
            //             Ok(deserialized_bytecodes) => {
            //                 if evm_state_sketch.bytecodes == deserialized_bytecodes {
            //                     info!("✅ Field 'bytecodes' serialization OK");
            //                 } else {
            //                     panic!("❌ Field 'bytecodes' differs after round-trip");
            //                 }
            //             }
            //             Err(bytecodes_err) => panic!("❌ Field 'bytecodes' deserialization failed: {:?}", bytecodes_err),
            //         }
            //     }
            //     Err(bytecodes_err) => panic!("❌ Field 'bytecodes' serialization failed: {:?}", bytecodes_err),
            // }

            // // Test receipts field
            // match bincode::serialize(&evm_state_sketch.receipts) {
            //     Ok(receipts_bytes) => {
            //         match bincode::deserialize::<_>(&receipts_bytes) {
            //             Ok(deserialized_receipts) => {
            //                 if evm_state_sketch.receipts == deserialized_receipts {
            //                     info!("✅ Field 'receipts' serialization OK");
            //                 } else {
            //                     panic!("❌ Field 'receipts' differs after round-trip");
            //                 }
            //             }
            //             Err(receipts_err) => panic!("❌ Field 'receipts' deserialization failed: {:?}", receipts_err),
            //         }
            //     }
            //     Err(receipts_err) => panic!("❌ Field 'receipts' serialization failed: {:?}", receipts_err),
            // }

            panic!("Failed to deserialize complete EvmSketchInput, but individual fields seem OK: {:?}", e);
        }
    }
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_bytes);
    stdin.write(&canoe_inputs);

    // Create a `NetworkProver`.
    let network_private_key = env::var("NETWORK_PRIVATE_KEY").unwrap_or_else(|_| {
        warn!("NETWORK_PRIVATE_KEY is not set, using default network private key");
        DEFAULT_NETWORK_PRIVATE_KEY.to_string()
    });
    let client = ProverClient::builder()
        .network()
        .private_key(&network_private_key)
        .build();
    let (pk, _vk) = client.setup(ELF);

    let proof = if mock_mode {
        // Execute the program using the `ProverClient.execute` method, without generating a proof.
        let (public_values, report) = client
            .execute(ELF, &stdin)
            .run()
            .expect("sp1-cc should have executed the ELF");
        info!(
            "executed program in mock mode with {} cycles and {} prover gas",
            report.total_instruction_count(),
            report
                .gas
                .expect("gas calculation is enabled by default in the executor")
        );

        // Create a mock aggregation proof with the public values.
        SP1ProofWithPublicValues::create_mock_proof(
            &pk,
            public_values,
            SP1ProofMode::Compressed,
            SP1_CIRCUIT_VERSION,
        )
    } else {
        let sp1_cc_proof_strategy = env_fulfillment_strategy(SP1_CC_PROOF_STRATEGY_ENV);

        // Generate the proof for the given program and input.
        let proof = client
            .prove(&pk, &stdin)
            .compressed()
            .strategy(sp1_cc_proof_strategy)
            .skip_simulation(true)
            .cycle_limit(1_000_000_000_000)
            .gas_limit(1_000_000_000_000)
            .timeout(Duration::from_secs(4 * 60 * 60))
            .run()
            .expect("sp1-cc should have produced a compressed proof");

        info!("generated sp1-cc proof in non-mock mode");

        proof
    };

    let elapsed = start.elapsed();
    info!(
        action = "sp1_cc_proof_generation",
        status = "completed",
        "sp1-cc commited: in elapsed_time {:?}",
        elapsed,
    );
    Ok(proof)
}
