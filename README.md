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


## Running the Prover

Use `cargo run` to execute the `src/main.rs` file.

It will take the files from the `data/` directory as input and perform the steps involved in the end to proof.

## Input File Format

To run this code, we have already provided an example `signature.json` and `merkle_data.json` in the `data/` directory. 

### signatures.json (values utilized to recover the eth address)
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

### merkle_data.json (valued used to generate the merkle proof for each leaf)
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

This tool is designed to be compatible with the SP1 zero-knowledge proof system. The verification uses three public values:

1. Message Digest (Public Input) - The hash of the signed message
2. Merkle Root (Public Input) - The root hash of the Merkle tree
3. Total Balance (Public Output) - The sum of balances across all verified addresses

There are also a few private inputs:

1. Signed Messages for each address
2. Balance held by each address

With a ZK proof, you can prove:
- You control a set of addresses with a specific total balance
- Those addresses are included in a specific Merkle tree
- You know the signatures corresponding to those addresses

All without revealing which addresses you control or their individual balances.
