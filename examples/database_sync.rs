//! Database replica synchronisation using Merkle trees (anti-entropy).
//!
//! Demonstrates how distributed databases like Cassandra and DynamoDB use
//! Merkle trees to efficiently detect which key ranges have diverged between
//! replicas — without transferring or comparing every record.
//!
//! Each replica builds a Merkle tree over its key-value pairs. To sync,
//! two replicas compare roots: if they match, the data is identical. If
//! they differ, the replicas walk down the tree level by level, narrowing
//! in on the differing subtrees until they identify the exact key ranges
//! that need repair.
//!
//! This reduces sync bandwidth from O(n) (send everything) to O(k log n),
//! where k is the number of differing keys.
//!
//! Run with: `cargo run --example database_sync`

use anyhow::{Context, Result};
use merkle_tree::MerkleTree;

/// A key-value record stored in a replica.
#[derive(Clone)]
struct Record {
    key: String,
    value: String,
}

impl Record {
    fn new(key: &str, value: &str) -> Self {
        Self {
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    /// Deterministic serialisation used as Merkle leaf data.
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.key.as_bytes());
        buf.push(b'=');
        buf.extend_from_slice(self.value.as_bytes());
        buf
    }
}

/// A database replica holding a set of key-value records and the
/// corresponding Merkle tree.
struct Replica {
    name: &'static str,
    records: Vec<Record>,
    tree: MerkleTree,
}

impl Replica {
    fn new(name: &'static str, records: Vec<Record>) -> Self {
        let leaves: Vec<Vec<u8>> = records.iter().map(|r| r.to_bytes()).collect();
        let tree = MerkleTree::build(&leaves);
        Self { name, records, tree }
    }

    fn root(&self) -> Result<merkle_tree::Hash> {
        self.tree
            .get_root_hash()
            .copied()
            .context("replica has no data")
    }

    /// Quick check: do two replicas have identical data?
    /// This is the first step in anti-entropy — if roots match, the replicas
    /// are fully in sync and no further work is needed.
    fn is_in_sync_with(&self, other: &Replica) -> Result<bool> {
        Ok(self.root()? == other.root()?)
    }

    /// Walk the leaf level to find which record indices differ between two
    /// replicas.
    ///
    /// NOTE: For simplicity this compares every leaf hash, making it O(n).
    /// A production implementation (e.g. Cassandra's anti-entropy) would
    /// instead walk the tree **level by level**, starting at the root's
    /// children and recursing only into subtrees whose hashes differ. That
    /// approach narrows down to the divergent leaves in O(k log n) hash
    /// comparisons (where k is the number of differing keys), which is
    /// critical when n is in the millions.
    fn find_divergent_keys(&self, other: &Replica) -> Result<Vec<usize>> {
        let common = self.records.len().min(other.records.len());

        let mut divergent = Vec::new();
        for i in 0..common {
            let hash_a = self.tree.get_leaf_hash(i).context("invalid leaf index")?;
            let hash_b = other.tree.get_leaf_hash(i).context("invalid leaf index")?;
            if hash_a != hash_b {
                divergent.push(i);
            }
        }
        // Records beyond the common range exist only on one side — all divergent.
        for i in common..self.records.len().max(other.records.len()) {
            divergent.push(i);
        }
        Ok(divergent)
    }

    /// Repair this replica by copying the given records from `source`,
    /// then rebuilding the Merkle tree to reflect the updated data.
    fn repair_from(&mut self, source: &Replica, indices: &[usize]) {
        for &idx in indices {
            self.records[idx] = source.records[idx].clone();
        }
        let leaves: Vec<Vec<u8>> = self.records.iter().map(|r| r.to_bytes()).collect();
        self.tree = MerkleTree::build(&leaves);
    }
}

fn main() -> Result<()> {
    // --- Build two replicas with identical data -----------------------------

    let shared_data = vec![
        Record::new("user:1001", r#"{"name":"Alice","email":"alice@example.com"}"#),
        Record::new("user:1002", r#"{"name":"Bob","email":"bob@example.com"}"#),
        Record::new("user:1003", r#"{"name":"Carol","email":"carol@example.com"}"#),
        Record::new("user:1004", r#"{"name":"Dave","email":"dave@example.com"}"#),
        Record::new("user:1005", r#"{"name":"Eve","email":"eve@example.com"}"#),
        Record::new("user:1006", r#"{"name":"Frank","email":"frank@example.com"}"#),
        Record::new("user:1007", r#"{"name":"Grace","email":"grace@example.com"}"#),
        Record::new("user:1008", r#"{"name":"Heidi","email":"heidi@example.com"}"#),
    ];

    let mut replica_a = Replica::new("DC-East", shared_data.clone());
    let replica_b = Replica::new("DC-West", shared_data.clone());

    // --- Scenario 1: Replicas are in sync -----------------------------------

    println!("=== Scenario 1: Replicas in sync ===\n");

    println!("  {} root: {}", replica_a.name, replica_a.root()?);
    println!("  {} root: {}", replica_b.name, replica_b.root()?);

    let in_sync = replica_a.is_in_sync_with(&replica_b)?;
    println!("\n  Roots match: {in_sync}");
    println!("  → No data transfer needed.\n");
    assert!(in_sync);

    // --- Scenario 2: Detect divergence after writes -------------------------

    println!("=== Scenario 2: Detect divergence after writes ===\n");

    // Simulate replica B receiving writes that replica A missed (e.g. due
    // to a network partition or delayed replication).
    let mut drifted_data = shared_data;
    drifted_data[2] = Record::new("user:1003", r#"{"name":"Carol","email":"carol@newdomain.com"}"#);
    drifted_data[6] = Record::new("user:1007", r#"{"name":"Grace","email":"grace.h@example.com","verified":true}"#);

    let replica_b_drifted = Replica::new("DC-West", drifted_data);

    println!("  {} root: {}", replica_a.name, replica_a.root()?);
    println!("  {} root: {}", replica_b_drifted.name, replica_b_drifted.root()?);

    let in_sync = replica_a.is_in_sync_with(&replica_b_drifted)?;
    println!("\n  Roots match: {in_sync}");
    println!("  → Divergence detected! Walking the tree to find differing keys...\n");
    assert!(!in_sync);

    let divergent = replica_a.find_divergent_keys(&replica_b_drifted)?;

    println!("  Found {} divergent key(s) out of {} total:", divergent.len(), replica_a.records.len());
    for &idx in &divergent {
        println!(
            "    [{idx}] key: {:12}  East: {:?}  →  West: {:?}",
            replica_a.records[idx].key,
            replica_a.records[idx].value,
            replica_b_drifted.records[idx].value,
        );
    }
    assert_eq!(divergent.len(), 2);
    assert_eq!(divergent, vec![2, 6]);

    println!(
        "\n  Only {}/{} records need to be transferred to repair the replica.\n",
        divergent.len(),
        replica_a.records.len()
    );

    // --- Scenario 3: After repair, replicas are back in sync ----------------

    println!("=== Scenario 3: After repair, replicas are back in sync ===\n");

    // "Repair" replica A by applying the writes from B.
    replica_a.repair_from(&replica_b_drifted, &divergent);

    println!("  {} root: {}", replica_a.name, replica_a.root()?);
    println!("  {} root: {}", replica_b_drifted.name, replica_b_drifted.root()?);

    let in_sync = replica_a.is_in_sync_with(&replica_b_drifted)?;
    println!("\n  Roots match: {in_sync}");
    println!("  → Replicas are synchronised.\n");
    assert!(in_sync);

    println!("All scenarios passed.");

    Ok(())
}
