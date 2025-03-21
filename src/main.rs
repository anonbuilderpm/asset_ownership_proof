//! Ethereum Signature and Merkle Proof Verification
//! 
//! This tool verifies two cryptographic properties:
//! 1. Ethereum signature verification - Confirms that signatures were created by the claimed addresses
//! 2. Merkle proof verification - Confirms that addresses and balances are included in a Merkle tree
//! 3. Balance aggregation - Calculates the total balance owned by the proven addresses

use std::fs;
use std::error::Error;
use sha3::{Digest, Keccak256};
use k256::{
    ecdsa::{Signature, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
};
use ecdsa_core::RecoveryId;
use serde::{Deserialize, Serialize};

// JSON Structures for input data
#[derive(Deserialize, Serialize, Debug)]
struct SignatureData {
    message: String,
    messageDigest: String,
    signatures: Vec<SignatureItem>,
}

#[derive(Deserialize, Serialize, Debug)]
struct SignatureItem {
    privateKey: String,
    address: String,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InclusionBranches {
    pub index: u32,
    pub proof: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Leaf {
    pub address: String,
    pub balance: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProofData {
    pub address: String,
    pub balance: u64,
    pub leaf_hash: String,
    pub inclusion_branches: InclusionBranches,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MerkleData {
    pub merkle_root: String,
    pub leaves: Vec<Leaf>,
    pub proofs: std::collections::HashMap<String, ProofData>,
}

// Recovers a public key from a signature and message digest
fn recover_pubkey_with_digest(message_digest_hex: &str, signature: &str) -> Result<String, Box<dyn Error>> {
    let sig_bytes = hex::decode(&signature[2..])?;
    let recovery_byte = sig_bytes[64];
    
    // Fix ECDSA error handling issues by mapping the errors
    let recovery_id = RecoveryId::try_from((recovery_byte - 27) as u8)
        .map_err(|e| format!("Invalid recovery ID: {:?}", e))?;
    
    let signature = Signature::try_from(&sig_bytes[..64])
        .map_err(|e| format!("Invalid signature: {:?}", e))?;
    
    let message_digest = hex_to_bytes32(message_digest_hex)?;
    
    let recovered_key = VerifyingKey::recover_from_prehash(&message_digest, &signature, recovery_id)
        .map_err(|e| format!("Recovery error: {:?}", e))?;
    
    let uncompressed = hex::encode(recovered_key.to_encoded_point(false).as_bytes());
    Ok(uncompressed)
}

// Convert a public key to an Ethereum address
fn pubkey_to_address(pubkey_hex: &str) -> Result<String, Box<dyn Error>> {
    let pubkey_bytes = hex::decode(pubkey_hex)?;
    let bytes_to_hash = if pubkey_bytes.len() > 0 && pubkey_bytes[0] == 4 {
        &pubkey_bytes[1..]
    } else {
        &pubkey_bytes
    };
    let mut hasher = Keccak256::new();
    hasher.update(bytes_to_hash);
    let hash = hasher.finalize();
    Ok(format!("0x{}", hex::encode(&hash[hash.len() - 20..])))
}

// Hash a leaf (address, balance) pair using keccak256
fn hash_leaf(address: &str, balance: u64) -> [u8; 32] {
    let address = address.to_lowercase();
    let balance = balance.to_string();
    let leaf_str = address + ":" + &balance;
    
    let mut hasher = Keccak256::new();
    hasher.update(leaf_str.as_bytes());
    let result = hasher.finalize();
    
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// Convert a hex string to a 32-byte array
fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let hex_str = if hex.starts_with("0x") { &hex[2..] } else { hex };
    let bytes = hex::decode(hex_str)?;
    
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()).into());
    }
    
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

// Compute the Merkle root from a leaf hash and inclusion proof
fn compute_inclusion_root(commitment: [u8; 32], proof: &InclusionBranches) -> Result<[u8; 32], Box<dyn Error>> {
    let bits = proof.index;
    let mut root = commitment;
    
    for (i, hash_hex) in proof.proof.iter().enumerate() {
        let hash = hex_to_bytes32(hash_hex)?;
        
        if bits & (1 << i) == 0 {
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(&root);
            input[32..].copy_from_slice(&hash);
            let mut hasher = Keccak256::new();
            hasher.update(input);
            root.copy_from_slice(&hasher.finalize()[..32]);
        } else {
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(&hash);
            input[32..].copy_from_slice(&root);
            let mut hasher = Keccak256::new();
            hasher.update(input);
            root.copy_from_slice(&hasher.finalize()[..32]);
        }
    }
    
    Ok(root)
}

fn main() -> Result<(), Box<dyn Error>> {
    // Load input data
    let sig_data: SignatureData = serde_json::from_str(&fs::read_to_string("data/signatures.json")?)?;
    let merkle_data: MerkleData = serde_json::from_str(&fs::read_to_string("data/merkle_data.json")?)?;
    let merkle_root_bytes = hex_to_bytes32(&merkle_data.merkle_root)?;
    
    println!("Message digest: {}", sig_data.messageDigest);
    println!("Merkle root: 0x{}", hex::encode(&merkle_root_bytes));
    
    // Verify all signatures and proofs
    let mut all_valid = true;
    let mut total_balance = 0u64;
    
    println!("\n=== Verifying signatures and balances ===");
    
    for (i, sig_item) in sig_data.signatures.iter().enumerate() {
        println!("\n--- Signature {} for address {} ---", i+1, sig_item.address);
        
        // Recover public key and address
        let pubkey = match recover_pubkey_with_digest(&sig_data.messageDigest, &sig_item.signature) {
            Ok(pk) => pk,
            Err(_) => { 
                println!("❌ Failed to recover public key");
                all_valid = false; 
                continue; 
            }
        };
        
        let recovered_address = match pubkey_to_address(&pubkey) {
            Ok(addr) => addr,
            Err(_) => { 
                println!("❌ Failed to derive address from public key");
                all_valid = false; 
                continue; 
            }
        };
        
        // Verify address match
        if recovered_address.to_lowercase() != sig_item.address.to_lowercase() {
            println!("❌ Address mismatch: expected {}, got {}", sig_item.address, recovered_address);
            all_valid = false;
            continue;
        }
        
        // Verify Merkle proof
        let proof_data = match merkle_data.proofs.get(&sig_item.address) {
            Some(data) => data,
            None => { 
                println!("❌ No Merkle proof found for address {}", sig_item.address);
                all_valid = false; 
                continue; 
            }
        };
        
        let computed_leaf_hash = hash_leaf(&recovered_address, proof_data.balance);
        let computed_root = match compute_inclusion_root(computed_leaf_hash, &proof_data.inclusion_branches) {
            Ok(root) => root,
            Err(_) => { 
                println!("❌ Failed to compute Merkle root");
                all_valid = false; 
                continue; 
            }
        };
        
        if computed_root != merkle_root_bytes {
            println!("❌ Root mismatch: expected 0x{}, got 0x{}", 
                    merkle_data.merkle_root, hex::encode(&computed_root));
            all_valid = false;
            continue;
        }
        
        // Add balance to the total
        total_balance += proof_data.balance;
        println!("✅ Verification successful - Address has {} tokens", proof_data.balance);
    }
    
    // Final result
    if all_valid {
        println!("\n✅ ALL VERIFICATIONS PASSED");
    } else {
        println!("\n❌ VERIFICATION FAILED - Not all signatures or proofs were valid");
    }
    
    // Output public values for zkProof
    println!("\n=== Public Values for ZK Proof ===");
    println!("1. Message Digest: {}", sig_data.messageDigest);
    println!("2. Merkle Root: 0x{}", merkle_data.merkle_root);
    println!("3. Total Balance: {}", total_balance);
    println!("\nProven claim: The signer controls keys with a total balance of {} tokens", total_balance);
    
    Ok(())
} 