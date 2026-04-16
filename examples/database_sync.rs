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

    fn root(&self) -> merkle_tree::Hash {
        *self.tree.get_root_hash().expect("non-empty replica")
    }
}

/// Compare two replicas and return the indices where their leaf hashes differ.
/// In a real system this would happen over the network, exchanging only hashes
/// at each tree level to narrow down the differences.
fn find_divergent_keys(a: &Replica, b: &Replica) -> Vec<usize> {
    assert_eq!(
        a.records.len(),
        b.records.len(),
        "replicas must have the same key count for this example"
    );

    let mut divergent = Vec::new();
    for i in 0..a.records.len() {
        let hash_a = a.tree.get_leaf_hash(i).expect("valid index");
        let hash_b = b.tree.get_leaf_hash(i).expect("valid index");
        if hash_a != hash_b {
            divergent.push(i);
        }
    }
    divergent
}

fn main() {
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

    let replica_a = Replica::new("DC-East", shared_data.clone());
    let replica_b = Replica::new("DC-West", shared_data.clone());

    println!("=== Scenario 1: Replicas in sync ===\n");

    println!("  {} root: {}", replica_a.name, replica_a.root());
    println!("  {} root: {}", replica_b.name, replica_b.root());

    let roots_match = replica_a.root() == replica_b.root();
    println!("\n  Roots match: {roots_match}");
    println!("  → No data transfer needed.\n");
    assert!(roots_match);

    // --- Simulate drift: some records diverge on replica B ------------------

    println!("=== Scenario 2: Detect divergence after writes ===\n");

    // Simulate replica B receiving writes that replica A missed (e.g. due
    // to a network partition or delayed replication).
    let mut drifted_data = shared_data.clone();
    drifted_data[2] = Record::new("user:1003", r#"{"name":"Carol","email":"carol@newdomain.com"}"#);
    drifted_data[6] = Record::new("user:1007", r#"{"name":"Grace","email":"grace.h@example.com","verified":true}"#);

    let replica_b_drifted = Replica::new("DC-West", drifted_data);

    println!("  {} root: {}", replica_a.name, replica_a.root());
    println!("  {} root: {}", replica_b_drifted.name, replica_b_drifted.root());

    let roots_match = replica_a.root() == replica_b_drifted.root();
    println!("\n  Roots match: {roots_match}");
    println!("  → Divergence detected! Walking the tree to find differing keys...\n");
    assert!(!roots_match);

    let divergent = find_divergent_keys(&replica_a, &replica_b_drifted);

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

    // --- Scenario 3: After repair, roots match again -------------------------

    println!("=== Scenario 3: After repair, replicas are back in sync ===\n");

    // "Repair" replica A by applying the writes from B
    let mut repaired_data = shared_data;
    for &idx in &divergent {
        repaired_data[idx] = replica_b_drifted.records[idx].clone();
    }
    let replica_a_repaired = Replica::new("DC-East", repaired_data);

    println!("  {} root: {}", replica_a_repaired.name, replica_a_repaired.root());
    println!("  {} root: {}", replica_b_drifted.name, replica_b_drifted.root());

    let roots_match = replica_a_repaired.root() == replica_b_drifted.root();
    println!("\n  Roots match: {roots_match}");
    println!("  → Replicas are synchronised.\n");
    assert!(roots_match);

    // --- Scenario 4: Verify individual record inclusion ----------------------

    println!("=== Scenario 4: Verify a specific record belongs to a replica ===\n");

    let idx = 4; // user:1005
    let leaf_hash = replica_a_repaired
        .tree
        .get_leaf_hash(idx)
        .expect("valid index");
    let proof = replica_a_repaired
        .tree
        .generate_proof(leaf_hash)
        .expect("leaf exists");
    let verified = proof.verify(&replica_a_repaired.root());

    println!(
        "  Record '{}' inclusion verified: {verified}  (proof: {} steps for {} records)\n",
        replica_a_repaired.records[idx].key,
        proof.steps.len(),
        replica_a_repaired.records.len(),
    );
    assert!(verified);

    println!("All scenarios passed.");
}
