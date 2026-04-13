//! Blockchain-style transaction verification using Merkle proofs.
//!
//! Demonstrates **Simplified Payment Verification (SPV)** as described in
//! Bitcoin whitepaper §7: a light client stores only block headers (including
//! the Merkle root) and can verify that a transaction is included in a block
//! by checking a compact O(log n) proof — without downloading the full block.
//!
//! Run with: `cargo run --example verify_transaction`

use merkle_tree::{MerkleTree, Proof};

// ── Domain types ─────────────────────────────────────────────────────────

/// A simplified blockchain transaction.
struct Transaction {
    from: &'static str,
    to: &'static str,
    value: u64,
    nonce: u64,
}

impl Transaction {
    /// Deterministic binary serialisation used as Merkle tree leaf data.
    ///
    /// A real implementation would use RLP, SSZ, or another canonical encoding;
    /// here we concatenate fields with a delimiter that cannot appear in the
    /// address/nonce representation to keep things simple.
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.from.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.to.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.value.to_le_bytes().as_slice());
        buf.push(b'|');
        buf.extend_from_slice(self.nonce.to_le_bytes().as_slice());
        buf
    }
}

/// A block on the full node: contains the complete transaction list and its
/// Merkle tree.
struct Block {
    id: &'static str,
    transactions: Vec<Transaction>,
    tree: MerkleTree,
}

impl Block {
    fn new(id: &'static str, transactions: Vec<Transaction>) -> Self {
        let leaves: Vec<Vec<u8>> = transactions.iter().map(|tx| tx.to_bytes()).collect();
        let tree = MerkleTree::build(&leaves);
        Self { id, transactions, tree }
    }
}

/// A full node stores complete blocks and can generate inclusion proofs.
struct FullNode {
    blocks: Vec<Block>,
}

impl FullNode {
    /// Generate a Merkle proof for `transaction_index` within `block_id`.
    fn proof_for(&self, block_id: &str, transaction_index: usize) -> Option<Proof> {
        let block = self.blocks.iter().find(|b| b.id == block_id)?;
        let leaf = block.tree.leaf_hash(transaction_index)?;
        block.tree.generate_proof(leaf)
    }
}

/// A light node stores only block IDs and Merkle roots — no full
/// transaction lists. This is the core of SPV: the light node can verify
/// any transaction's inclusion using only a compact proof received from a
/// full node, without trusting the full node with anything beyond the proof
/// data itself.
struct LightNode {
    headers: Vec<(&'static str, merkle_tree::Hash)>,
}

impl LightNode {
    fn from_full_node(full: &FullNode) -> Self {
        let headers = full
            .blocks
            .iter()
            .map(|b| (b.id, *b.tree.root().expect("non-empty block")))
            .collect();
        Self { headers }
    }

    /// Verify a transaction proof against the stored root for `block_id`.
    fn verify(&self, block_id: &str, proof: &Proof) -> bool {
        self.headers
            .iter()
            .find(|(id, _)| *id == block_id)
            .is_some_and(|(_, root)| proof.verify(root))
    }
}

// ── Main ─────────────────────────────────────────────────────────────────

fn main() {
    // Build two blocks with different transactions.
    let block_a = Block::new(
        "block-1",
        vec![
            Transaction { from: "0xAlice", to: "0xBob",   value: 50, nonce: 1 },
            Transaction { from: "0xBob",   to: "0xCarol", value: 30, nonce: 1 },
            Transaction { from: "0xCarol", to: "0xDave",  value: 10, nonce: 1 },
            Transaction { from: "0xDave",  to: "0xAlice", value:  5, nonce: 1 },
            Transaction { from: "0xAlice", to: "0xDave",  value: 20, nonce: 2 },
        ],
    );
    let block_b = Block::new(
        "block-2",
        vec![
            Transaction { from: "0xEve",  to: "0xAlice", value: 100, nonce: 1 },
            Transaction { from: "0xAlice", to: "0xBob",   value:  75, nonce: 3 },
        ],
    );

    let full_node = FullNode {
        blocks: vec![block_a, block_b],
    };
    let light_node = LightNode::from_full_node(&full_node);

    // ── Scenario 1: Successful membership verification ───────────────
    // A client wants to confirm that the 3rd transaction (index 2) in
    // block-1 was really included. The full node provides a proof; the
    // light node verifies it against the stored Merkle root.

    println!("=== Scenario 1: Successful membership verification ===\n");

    let proof = full_node
        .proof_for("block-1", 2)
        .expect("transaction exists in block");

    let verified = light_node.verify("block-1", &proof);
    println!("Transaction in block-1 verified: {verified}");
    assert!(verified);

    // Show logarithmic proof size: only a handful of hashes are needed
    // regardless of the number of transactions in the block.
    let tx_count = full_node.blocks[0].transactions.len();
    println!(
        "Proof size: {} steps for {} transactions (log₂({}) ≈ {:.1})\n",
        proof.steps.len(),
        tx_count,
        tx_count,
        (tx_count as f64).log2(),
    );

    // ── Scenario 2: Tamper detection ─────────────────────────────────
    // An attacker modifies a proof step. The Merkle root recomputed from
    // the tampered proof will not match the block's stored root, so
    // verification fails.

    println!("=== Scenario 2: Tamper detection ===\n");

    let mut tampered_proof = proof.clone();
    tampered_proof.steps[0].hash = merkle_tree::hash(b"tampered-data");

    let tampered_verified = light_node.verify("block-1", &tampered_proof);
    println!("Tampered proof verified: {tampered_verified}");
    assert!(!tampered_verified);
    println!();

    // ── Scenario 3: Cross-block rejection ────────────────────────────
    // A proof generated for block-2 cannot verify against block-1's root.
    // Each block has its own Merkle tree, so proofs are scoped to the
    // block they were generated from.

    println!("=== Scenario 3: Cross-block rejection ===\n");

    let block_b_proof = full_node
        .proof_for("block-2", 0)
        .expect("transaction exists in block-2");

    let cross_verified = light_node.verify("block-1", &block_b_proof);
    println!("Block-2 proof verified against block-1: {cross_verified}");
    assert!(!cross_verified);

    // But the same proof succeeds against its own block.
    let own_block_verified = light_node.verify("block-2", &block_b_proof);
    println!("Block-2 proof verified against block-2: {own_block_verified}");
    assert!(own_block_verified);
    println!();

    println!("All scenarios passed.");
}
