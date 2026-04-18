//! Blockchain-style transaction verification using Merkle proofs.
//!
//! Demonstrates **Simplified Payment Verification (SPV)** as described in
//! Bitcoin whitepaper §7: a light client stores only block headers (including
//! the Merkle root) and can verify that a transaction is included in a block
//! by checking a compact O(log n) proof — without downloading the full block.
//!
//! Run with: `cargo run --example verify_transaction`

use anyhow::{Context, Result};
use merkle_tree::{MerkleTree, Proof};

/// A simplified blockchain transaction.
///
/// The `nonce` here is a **per-sender sequence number** (as in Ethereum's
/// account-based model) that prevents replay attacks and orders transactions
/// from the same sender.  This is distinct from the **block-level nonce**
/// used in Proof-of-Work mining (e.g. Bitcoin), which lives in the block
/// header and is iterated by miners to meet the difficulty target.
struct Transaction {
    from: String,
    to: String,
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
    id: String,
    transactions: Vec<Transaction>,
    tree: MerkleTree,
}

impl Block {
    fn new(id: impl Into<String>, transactions: Vec<Transaction>) -> Self {
        let id = id.into();
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
        let leaf = block.tree.get_leaf_hash(transaction_index)?;
        block.tree.generate_proof(leaf)
    }
}

/// The minimal per-block metadata a light client needs: the block
/// identifier and the Merkle root of its transaction tree.
///
/// In a real blockchain (e.g. Bitcoin, Ethereum) a block header carries
/// additional fields (previous-block hash, timestamp, nonce, …); here we
/// keep only what is required for SPV-style verification.
struct BlockHeader {
    id: String,
    merkle_root: merkle_tree::Hash,
}

/// A light node stores only block headers — no full transaction lists.
/// This is the core of SPV: the light node can verify any transaction's
/// inclusion using only a compact proof received from a full node, without
/// trusting the full node with anything beyond the proof data itself.
struct LightNode {
    headers: Vec<BlockHeader>,
}

impl LightNode {
    fn from_full_node(full: &FullNode) -> Result<Self> {
        let headers = full
            .blocks
            .iter()
            .map(|b| {
                let merkle_root = *b
                    .tree
                    .get_root_hash()
                    .with_context(|| format!("block {} has no transactions", b.id))?;
                Ok(BlockHeader {
                    id: b.id.clone(),
                    merkle_root,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { headers })
    }

    /// Verify a transaction proof against the stored root for `block_id`.
    fn verify(&self, block_id: &str, proof: &Proof) -> bool {
        self.headers
            .iter()
            .find(|h| h.id == block_id)
            .is_some_and(|h| proof.verify(&h.merkle_root))
    }
}

fn main() -> Result<()> {
    // Build two blocks with different transactions.
    let block_a = Block::new(
        "block-1",
        vec![
            Transaction { from: "0xAlice".into(), to: "0xBob".into(),   value: 50, nonce: 1 },
            Transaction { from: "0xBob".into(),   to: "0xCarol".into(), value: 30, nonce: 1 },
            Transaction { from: "0xCarol".into(), to: "0xDave".into(),  value: 10, nonce: 1 },
            Transaction { from: "0xDave".into(),  to: "0xAlice".into(), value:  5, nonce: 1 },
            Transaction { from: "0xAlice".into(), to: "0xDave".into(),  value: 20, nonce: 2 },
        ],
    );
    let block_b = Block::new(
        "block-2",
        vec![
            Transaction { from: "0xEve".into(),   to: "0xAlice".into(), value: 100, nonce: 1 },
            Transaction { from: "0xAlice".into(), to: "0xBob".into(),   value:  75, nonce: 3 },
        ],
    );

    let full_node = FullNode {
        blocks: vec![block_a, block_b],
    };
    let light_node = LightNode::from_full_node(&full_node)?;

    // A client wants to confirm that the 3rd transaction (index 2) in
    // block-1 was really included. The full node provides a proof; the
    // light node verifies it against the stored Merkle root.

    println!("=== Scenario 1: Successful membership verification ===\n");

    let proof = full_node
        .proof_for("block-1", 2)
        .context("transaction at index 2 not found in block-1")?;

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

    // A proof generated for block-2 cannot verify against block-1's root.
    // Each block has its own Merkle tree, so proofs are scoped to the
    // block they were generated from.

    println!("=== Scenario 3: Cross-block rejection ===\n");

    let block_b_proof = full_node
        .proof_for("block-2", 0)
        .context("transaction at index 0 not found in block-2")?;

    let cross_verified = light_node.verify("block-1", &block_b_proof);
    println!("Block-2 proof verified against block-1: {cross_verified}");
    assert!(!cross_verified);

    // But the same proof succeeds against its own block.
    let own_block_verified = light_node.verify("block-2", &block_b_proof);
    println!("Block-2 proof verified against block-2: {own_block_verified}");
    assert!(own_block_verified);
    println!();

    println!("All scenarios passed.");
    Ok(())
}
