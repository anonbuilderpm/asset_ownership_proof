# Token Ownership Proof

This tool cryptographically verifies that a user controls Ethereum addresses containing a specific total balance, without revealing which addresses they control.

## What This Tool Does

This verifier performs three critical functions:

### 1. Signature Verification
- Recovers the public key from each Ethereum signature
- Derives the Ethereum address from the public key
- Confirms it matches the expected address in the signature data

### 2. Merkle Proof Verification
- Computes the leaf hash from each address and balance pair
- Verifies this leaf is included in the Merkle tree using the inclusion proof
- Confirms the computed Merkle root matches the expected root

### 3. Balance Aggregation
- Calculates the total balance across all verifiably owned addresses
- Produces a provable claim about the total assets controlled by the signer

## Key Use Case

The primary purpose of this tool is to allow users to prove they control a certain total amount of tokens across multiple addresses without revealing exactly which addresses those are. This is valuable for:

- Proving eligibility for airdrops or token claims
- Demonstrating financial requirements without exposing wealth details
- Verifying token holdings for governance voting power
- Creating zero-knowledge proofs about asset ownership

## Prerequisites

- Rust and Cargo installed
- Input files in the correct format

## Running the Verifier

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/ethereum-sig-verifier.git
   cd ethereum-sig-verifier
   ```

2. Run the verifier:
   ```
   cargo run
   ```

The verifier will read the input files from the `data/` directory and perform the verification.

## Input File Format

### signatures.json
```json
{
  "message": "Original message text",
  "messageDigest": "0x[32-byte hex of the message hash]",
  "signatures": [
    {
      "privateKey": "[private key used to sign - only included for reference]",
      "address": "0x[ethereum address]",
      "signature": "0x[65-byte ethereum signature]"
    },
    ...
  ]
}
```

### merkle_data.json
```json
{
  "merkle_root": "[32-byte hex of merkle root without 0x]",
  "leaves": [...],
  "proofs": {
    "0x[ethereum address]": {
      "address": "0x[ethereum address]",
      "balance": [numeric balance],
      "leaf_hash": "0x[32-byte hex of leaf hash]",
      "inclusion_branches": {
        "index": [numeric index],
        "proof": [
          "[32-byte hex of each merkle branch without 0x]",
          ...
        ]
      }
    },
    ...
  }
}
```

## Usage for Zero-Knowledge Proofs

This tool is designed to be compatible with the SP1 zero-knowledge proof system. The verification outputs three public values that can be used as public inputs for a ZK proof:

1. Message Digest - The hash of the signed message
2. Merkle Root - The root hash of the Merkle tree
3. Total Balance - The sum of balances across all verified addresses

With a ZK proof, you can prove:
- You control a set of addresses with a specific total balance
- Those addresses are included in a specific Merkle tree
- You know the signatures corresponding to those addresses

All without revealing which addresses you control or their individual balances.
