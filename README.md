# merkle-tree

A SHA-256 Merkle tree implementation in Rust for blockchain and data integrity
verification.

## Features

- **SHA-256 hashing** with domain separation (leaf vs. internal node) to prevent
  second-preimage attacks (per RFC 6962 §2.1)
- **O(log n) inclusion proofs** — verify membership with only `log₂(n)` sibling
  hashes instead of the full dataset
- **Tamper-evident** — any change to a leaf invalidates the root hash
- **Zero-copy `Hash` type** — 32-byte stack-allocated newtype with `Copy` semantics
- **Generic input** — accepts any `AsRef<[u8]>` (`&str`, `String`, `Vec<u8>`, etc.)

## Usage

```rust
use merkle_tree::{MerkleTree, hash};

// Build a tree from transaction data
let tree = MerkleTree::build(&["alice→bob: 50", "bob→carol: 30", "carol→dave: 10"]);
let root = tree.root().expect("non-empty tree has a root");

// Generate an inclusion proof for a specific leaf
let leaf = tree.leaf_hash(0).expect("leaf exists");
let proof = tree.generate_proof(leaf).expect("proof exists");

// Verify the proof against the root hash
assert!(proof.verify(root));

// Tampered data won't verify
let other_tree = MerkleTree::build(&["fake_tx"]);
assert!(!proof.verify(other_tree.root().unwrap()));
```

## Run the example

```sh
cargo run --example verify_transaction
```

## References

- Ralph C. Merkle, *"A Digital Signature Based on a Conventional Encryption
  Function"*, CRYPTO '87
- US Patent 4,309,569 — *"Method of providing digital signatures"* (1982)
- Satoshi Nakamoto, *"Bitcoin: A Peer-to-Peer Electronic Cash System"*, §7 —
  Reclaiming Disk Space
- RFC 6962 — *"Certificate Transparency"*, §2.1 — Merkle Tree hash domain separation
