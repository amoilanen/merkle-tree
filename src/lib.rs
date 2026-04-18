//! A SHA-256 Merkle tree for data integrity verification and inclusion proofs.
//!
//! [Merkle trees](https://en.wikipedia.org/wiki/Merkle_tree) are hash-based data structures
//! that allow efficient and secure verification of data integrity. They are widely used in
//! distributed systems, blockchains, and file verification protocols.
//!
//! # Core properties
//!
//! - **Tamper-evident**: any change to a leaf invalidates the root hash.
//! - **O(log n) inclusion proofs**: a leaf's membership can be verified with only
//!   `log₂(n)` sibling hashes instead of the full dataset.
//!
//! # References
//!
//! - Ralph C. Merkle, *"A Digital Signature Based on a Conventional Encryption Function"*,
//!   CRYPTO '87. <https://link.springer.com/chapter/10.1007/3-540-48184-2_32>
//! - US Patent 4,309,569 — *"Method of providing digital signatures"* (1982).
//! - Satoshi Nakamoto, *"Bitcoin: A Peer-to-Peer Electronic Cash System"*, §7 — Reclaiming
//!   Disk Space. <https://bitcoin.org/bitcoin.pdf>
//!
//! # Usage
//!
//! ```
//! use merkle_tree::MerkleTree;
//!
//! let tree = MerkleTree::build(&["alice→bob: 50", "bob→carol: 30"]);
//! let root = tree.get_root_hash().expect("non-empty tree has a root");
//!
//! let leaf = tree.get_leaf_hash(0).expect("leaf exists");
//! let proof = tree.generate_proof(leaf).expect("proof exists");
//! assert!(proof.verify(root));
//! ```

use sha2::{Digest, Sha256};
use std::fmt;

/// A SHA-256 digest (32 bytes).
///
/// This is the fundamental unit of data throughout the tree. It wraps a
/// fixed-size byte array, avoiding heap allocations and enabling `Copy`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Returns a reference to the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Hash {
    /// Short hex representation (first 4 bytes / 8 hex chars) for readable debug output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({}…)", &format!("{self}")[..8])
    }
}

impl fmt::Display for Hash {
    /// Full lowercase hex string (64 characters).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Whether a sibling is to the left or right of the path node in the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Left,
    Right,
}

/// A single step in a Merkle inclusion proof: a sibling hash and its position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofStep {
    /// The sibling hash at this tree level.
    pub hash: Hash,
    /// The position of the sibling relative to the path node.
    pub direction: Direction,
}

/// A Merkle inclusion proof: a leaf hash plus the sibling hashes needed to
/// recompute the root.
///
/// The proof encodes a path from a specific leaf up to the root. To verify
/// membership, recompute the root by hashing the leaf with each successive
/// sibling (respecting left/right ordering) and compare with the expected root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// The leaf hash this proof is for.
    pub leaf: Hash,
    /// Sibling hashes from leaf level up to (but not including) the root.
    pub steps: Vec<ProofStep>,
}

/// A SHA-256 Merkle tree built from leaf data.
///
/// Internally stores every level of hashes from root (index 0) down to
/// the leaves (last index). This enables proof generation by walking
/// from the leaf level upward.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Tree levels, root-first. `levels[0]` contains the single root hash
    /// (or is empty for an empty tree), and `levels[len-1]` contains the
    /// leaf hashes.
    levels: Vec<Vec<Hash>>,
    /// Number of original leaves (before odd-leaf duplication).
    leaf_count: usize,
}

/// Hash arbitrary data with SHA-256.
///
/// Use this to produce leaf hashes before inserting them into a tree or
/// when looking up a proof.
///
/// ```
/// let h = merkle_tree::hash(b"hello");
/// assert_eq!(h.to_string().len(), 64); // 256-bit hex
/// ```
pub fn hash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Hash(hasher.finalize().into())
}

/// Domain-separated leaf hash: `SHA-256(0x00 || data)`.
///
/// Use this to hash raw data exactly as [`MerkleTree::build`] does, e.g. to
/// verify that downloaded content matches a proof's leaf hash.
///
/// The `0x00` prefix prevents second-preimage attacks where an attacker
/// crafts leaf data that collides with an internal node hash.
///
/// Reference: *Certificate Transparency* (RFC 6962, §2.1) uses domain
/// separation for exactly this reason.
pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    Hash(hasher.finalize().into())
}

/// Domain-separated internal node hash: `SHA-256(0x01 || left || right)`.
///
/// The `0x01` prefix ensures internal nodes live in a different hash domain
/// than leaves, preventing second-preimage attacks.
fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left.0);
    hasher.update(right.0);
    Hash(hasher.finalize().into())
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data.
    ///
    /// Each leaf is hashed with domain-separated SHA-256 (`SHA-256(0x00 || data)`).
    /// When a level has an odd number of nodes, the last node is duplicated
    /// before pairing — this follows the approach used in Bitcoin's Merkle
    /// tree construction (see Bitcoin Core, `ComputeMerkleRoot`).
    ///
    /// An empty input produces a tree where [`root()`](Self::root) returns `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::build(&["tx1", "tx2", "tx3"]);
    /// assert!(tree.get_root_hash().is_some());
    ///
    /// let empty = MerkleTree::build::<&[u8]>(&[]);
    /// assert!(empty.get_root_hash().is_none());
    /// ```
    pub fn build<T: AsRef<[u8]>>(leaves: &[T]) -> MerkleTree {
        if leaves.is_empty() {
            return MerkleTree {
                levels: vec![vec![]],
                leaf_count: 0,
            };
        }

        let leaf_count = leaves.len();

        let mut current_level: Vec<Hash> = leaves.iter().map(|l| hash_leaf(l.as_ref())).collect();
        let mut levels: Vec<Vec<Hash>> = Vec::new();

        while current_level.len() > 1 {
            // Duplicate the last node when the level has an odd count, matching
            // Bitcoin's Merkle tree construction which duplicates the trailing
            // hash so every node has a pair.
            if current_level.len() % 2 != 0 {
                if let Some(&last) = current_level.last() {
                    current_level.push(last);
                }
            }
            levels.push(current_level.clone());

            current_level = current_level
                .chunks_exact(2)
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect();
        }

        levels.push(current_level);
        levels.reverse();

        MerkleTree { levels, leaf_count }
    }

    /// Returns the number of leaves in the tree (before any odd-leaf duplication).
    pub fn len(&self) -> usize {
        self.leaf_count
    }

    /// Returns `true` if the tree was built from empty input.
    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    /// Returns the domain-separated hash of the leaf at the given index,
    /// or `None` if the index is out of bounds.
    ///
    /// This is the hash stored internally at the leaf level, suitable for
    /// passing to [`generate_proof`](Self::generate_proof).
    pub fn get_leaf_hash(&self, index: usize) -> Option<&Hash> {
        if index >= self.leaf_count {
            return None;
        }
        self.levels.last().and_then(|level| level.get(index))
    }

    /// Returns the root hash, or `None` if the tree was built from empty input.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::build(&["a", "b"]);
    /// let root = tree.get_root_hash().expect("non-empty tree");
    /// assert_eq!(root.to_string().len(), 64);
    /// ```
    pub fn get_root_hash(&self) -> Option<&Hash> {
        self.levels.first().and_then(|level| level.first())
    }

    /// Generate an inclusion proof for the given leaf hash.
    ///
    /// Returns `None` if `leaf_hash` is not present at the leaf level of the tree.
    /// The proof contains the sibling hashes needed to recompute the root.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::build(&["tx1", "tx2", "tx3"]);
    /// let root = tree.get_root_hash().unwrap();
    ///
    /// // The tree hashes leaves internally with domain separation.
    /// // Use `leaf_hash` to obtain the correct hash for proof lookup.
    /// let leaf = tree.get_leaf_hash(0).unwrap();
    /// let proof = tree.generate_proof(&leaf).expect("leaf is in the tree");
    /// assert!(proof.verify(root));
    /// ```
    pub fn generate_proof(&self, leaf_hash: &Hash) -> Option<Proof> {
        let leaf_level = self.levels.last()?;
        let mut position = leaf_level.iter().position(|h| h == leaf_hash)?;

        let mut steps = Vec::with_capacity(self.levels.len().saturating_sub(1));

        // Walk from leaf level upward toward the root, collecting each sibling
        // hash. `levels[0]` is the root and `levels[last]` is the leaf level.
        // At each level we find the sibling of our current position, record it,
        // then halve the position to move to the parent level.
        for depth in (1..self.levels.len()).rev() {
            let level = &self.levels[depth];
            // Nodes are paired (0-1, 2-3, …): even positions pair with the next
            // node (right sibling), odd positions pair with the previous one (left sibling).
            let sibling_pos = if position % 2 == 0 {
                position + 1
            } else {
                position - 1
            };
            let sibling_hash = level[sibling_pos];
            let direction = if position % 2 == 0 {
                Direction::Right
            } else {
                Direction::Left
            };
            steps.push(ProofStep {
                hash: sibling_hash,
                direction,
            });
            position /= 2;
        }

        Some(Proof {
            leaf: *leaf_hash,
            steps,
        })
    }
}

impl Proof {
    /// Recompute the root hash from this proof's leaf and steps.
    ///
    /// Starting from the leaf hash, each step provides a sibling hash and
    /// its direction. The pair is combined with domain-separated hashing (preserving
    /// left/right order) to produce the parent hash, until the root is reached.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::build(&["a", "b", "c", "d"]);
    /// let root = tree.get_root_hash().unwrap();
    /// let proof = tree.generate_proof(tree.get_leaf_hash(0).unwrap()).unwrap();
    /// assert_eq!(proof.compute_root(), *root);
    /// ```
    pub fn compute_root(&self) -> Hash {
        self.steps.iter().fold(self.leaf, |current, step| {
            match step.direction {
                // Sibling is on the left → sibling comes first.
                Direction::Left => hash_pair(&step.hash, &current),
                // Sibling is on the right → current comes first.
                Direction::Right => hash_pair(&current, &step.hash),
            }
        })
    }

    /// Verify that this proof's leaf belongs to a tree with the given root.
    ///
    /// This recomputes the root from the proof and checks equality.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let tree = MerkleTree::build(&["tx1", "tx2", "tx3", "tx4"]);
    /// let root = tree.get_root_hash().unwrap();
    /// let proof = tree.generate_proof(tree.get_leaf_hash(2).unwrap()).unwrap();
    /// assert!(proof.verify(root));
    ///
    /// // A different tree's root will not match:
    /// let other = MerkleTree::build(&["x", "y"]);
    /// assert!(!proof.verify(other.get_root_hash().unwrap()));
    /// ```
    pub fn verify(&self, expected_root: &Hash) -> bool {
        self.compute_root() == *expected_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    /// Helper: decode a hex string into a `Hash`.
    fn h(hex_str: &str) -> anyhow::Result<Hash> {
        let bytes: Vec<u8> = hex::decode(hex_str)?;
        let len = bytes.len();
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {len}"))?;
        Ok(Hash::from(bytes))
    }

    // Precomputed hashes (domain-separated: leaf = SHA-256(0x00 || data),
    // pair = SHA-256(0x01 || left || right)).
    const LEAF_A: &str = "022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c";
    const LEAF_C: &str = "597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8";
    const ROOT_AB: &str = "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb";
    const ROOT_ABCD: &str = "33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0";
    const ROOT_ABC: &str = "e9636069c740c9ff51625b01a0b040396d265a9b920cc6febdfa5ecc9f58ecce";

    #[test]
    fn empty_tree_has_no_root() {
        let tree = MerkleTree::build::<&[u8]>(&[]);
        assert!(tree.get_root_hash().is_none());
    }

    #[test]
    fn single_leaf_tree_root_equals_leaf_hash() -> anyhow::Result<()> {
        let tree = MerkleTree::build(&["a"]);
        assert_eq!(tree.levels.len(), 1);
        assert_eq!(*tree.get_root_hash().context("missing root")?, h(LEAF_A)?);
        Ok(())
    }

    #[test]
    fn two_leaf_tree_has_root_and_leaf_levels() -> anyhow::Result<()> {
        let tree = MerkleTree::build(&["a", "b"]);
        assert_eq!(tree.levels.len(), 2); // root + leaves
        assert_eq!(tree.levels[0].len(), 1);
        assert_eq!(tree.levels[1].len(), 2);
        assert_eq!(*tree.get_root_hash().context("missing root")?, h(ROOT_AB)?);
        Ok(())
    }

    #[test]
    fn four_leaf_tree_has_three_levels_and_known_root() -> anyhow::Result<()> {
        let tree = MerkleTree::build(&["a", "b", "c", "d"]);
        assert_eq!(tree.levels.len(), 3); // root, 2 internal, 4 leaves
        assert_eq!(tree.levels[0].len(), 1);
        assert_eq!(tree.levels[2].len(), 4);
        assert_eq!(*tree.get_root_hash().context("missing root")?, h(ROOT_ABCD)?);
        Ok(())
    }

    #[test]
    fn power_of_two_leaves_produce_balanced_levels() {
        let tree = MerkleTree::build(&["a", "b", "c", "d", "e", "f", "g", "h"]);
        assert_eq!(tree.levels.len(), 4);
        assert_eq!(tree.levels[0].len(), 1);
        assert_eq!(tree.levels[1].len(), 2);
        assert_eq!(tree.levels[2].len(), 4);
        assert_eq!(tree.levels[3].len(), 8);
    }

    #[test]
    fn odd_leaf_count_duplicates_last() -> anyhow::Result<()> {
        // 3 leaves → [a, b, c, c_dup] at leaf level
        let tree = MerkleTree::build(&["a", "b", "c"]);
        assert_eq!(tree.levels.len(), 3);
        // Leaf level has 4 entries (3 + 1 duplicate)
        assert_eq!(tree.levels[2].len(), 4);
        assert_eq!(tree.levels[2][2], tree.levels[2][3], "last leaf must be duplicated");
        assert_eq!(*tree.get_root_hash().context("missing root")?, h(ROOT_ABC)?);
        Ok(())
    }

    #[test]
    fn five_leaves_duplicate_at_each_odd_level() {
        let tree = MerkleTree::build(&["a", "b", "c", "d", "e"]);
        // 5 leaves → 6 (dup) → 3 pairs → 4 (dup) → 2 → 1
        assert_eq!(tree.levels.len(), 4);
        assert_eq!(tree.levels[0].len(), 1);
        assert_eq!(tree.levels[3].len(), 6);
    }

    #[test]
    fn same_input_produces_identical_root() {
        let t1 = MerkleTree::build(&["x", "y", "z"]);
        let t2 = MerkleTree::build(&["x", "y", "z"]);
        assert_eq!(t1.get_root_hash(), t2.get_root_hash());
    }

    #[test]
    fn generate_proof_returns_correct_leaf_hash() -> anyhow::Result<()> {
        let tree = MerkleTree::build(&["a", "b", "c", "d"]);
        let leaf = hash_leaf(b"c");
        let proof = tree.generate_proof(&leaf).context("proof not found")?;
        assert_eq!(proof.leaf, h(LEAF_C)?);
        Ok(())
    }

    #[test]
    fn generate_proof_returns_none_for_missing_leaf() {
        let tree = MerkleTree::build(&["a", "b"]);
        let missing = hash_leaf(b"z");
        assert!(tree.generate_proof(&missing).is_none());
    }

    #[test]
    fn generate_proof_returns_none_on_empty_tree() {
        let tree = MerkleTree::build::<&[u8]>(&[]);
        let leaf = hash_leaf(b"a");
        assert!(tree.generate_proof(&leaf).is_none());
    }

    #[test]
    fn every_leaf_proof_verifies_against_root() -> anyhow::Result<()> {
        let items = &["a", "b", "c", "d"];
        let tree = MerkleTree::build(items);
        let root = tree.get_root_hash().context("missing root")?;

        for item in items {
            let leaf = hash_leaf(item.as_bytes());
            let proof = tree.generate_proof(&leaf).context("proof not found")?;
            assert_eq!(proof.leaf, leaf);
            assert!(proof.verify(root), "proof failed for leaf '{item}'");
        }
        Ok(())
    }

    #[test]
    fn compute_root_from_proof_matches_tree_root() -> anyhow::Result<()> {
        let tree = MerkleTree::build(&["a", "b", "c", "d"]);
        let root = tree.get_root_hash().context("missing root")?;
        let leaf = hash_leaf(b"a");
        let proof = tree.generate_proof(&leaf).context("proof not found")?;
        assert_eq!(proof.compute_root(), *root);
        Ok(())
    }

    #[test]
    fn tampered_sibling_hash_invalidates_proof() -> anyhow::Result<()> {
        let tree = MerkleTree::build(&["a", "b", "c", "d"]);
        let root = tree.get_root_hash().context("missing root")?;
        let leaf = hash_leaf(b"a");
        let mut proof = tree.generate_proof(&leaf).context("proof not found")?;
        proof.steps[0].hash = hash(b"tampered");
        assert!(!proof.verify(root));
        Ok(())
    }

    #[test]
    fn tampered_leaf_hash_invalidates_proof() -> anyhow::Result<()> {
        let tree = MerkleTree::build(&["a", "b", "c", "d"]);
        let root = tree.get_root_hash().context("missing root")?;
        let leaf = hash_leaf(b"a");
        let mut proof = tree.generate_proof(&leaf).context("proof not found")?;
        proof.leaf = hash_leaf(b"TAMPERED");
        assert!(!proof.verify(root));
        Ok(())
    }

    #[test]
    fn proof_from_one_tree_fails_against_different_tree_root() -> anyhow::Result<()> {
        let tree1 = MerkleTree::build(&["a", "b"]);
        let tree2 = MerkleTree::build(&["x", "y"]);
        let leaf = hash_leaf(b"a");
        let proof = tree1.generate_proof(&leaf).context("proof not found")?;
        assert!(!proof.verify(tree2.get_root_hash().context("missing root")?));
        Ok(())
    }

    #[test]
    fn flipped_sibling_direction_invalidates_proof() -> anyhow::Result<()> {
        let tree = MerkleTree::build(&["a", "b", "c", "d"]);
        let root = tree.get_root_hash().context("missing root")?;
        let leaf = hash_leaf(b"a");
        let mut proof = tree.generate_proof(&leaf).context("proof not found")?;
        // Flip the direction of the first step
        proof.steps[0].direction = match proof.steps[0].direction {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        };
        assert!(!proof.verify(root));
        Ok(())
    }

    #[test]
    fn single_leaf_proof_has_no_steps_and_verifies() -> anyhow::Result<()> {
        let tree = MerkleTree::build(&["only"]);
        let root = tree.get_root_hash().context("missing root")?;
        let leaf = hash_leaf(b"only");
        let proof = tree.generate_proof(&leaf).context("proof not found")?;
        assert!(proof.steps.is_empty(), "single-leaf proof needs no steps");
        assert!(proof.verify(root));
        assert_eq!(proof.compute_root(), *root);
        Ok(())
    }

    #[test]
    fn odd_leaf_duplication_does_not_break_proof() -> anyhow::Result<()> {
        // In a 3-leaf tree [a, b, c], "c" is duplicated to make [a, b, c, c].
        // Proof for "c" should still verify correctly.
        let tree = MerkleTree::build(&["a", "b", "c"]);
        let root = tree.get_root_hash().context("missing root")?;
        let leaf_c = hash_leaf(b"c");
        let proof = tree.generate_proof(&leaf_c).context("proof not found")?;
        assert!(proof.verify(root));
        Ok(())
    }

    #[test]
    fn ten_thousand_leaves_proof_depth_is_log2_n() -> anyhow::Result<()> {
        let n = 10000;
        let leaves: Vec<String> = (0..n).map(|i| format!("leaf_{i}")).collect();
        let refs: Vec<&str> = leaves.iter().map(|s| s.as_str()).collect();
        let tree = MerkleTree::build(&refs);
        let root = tree.get_root_hash().context("missing root")?;

        let target = hash_leaf(b"leaf_500");
        let proof = tree.generate_proof(&target).context("proof not found")?;

        // Proof steps should be ⌈log₂(n)⌉ = 10 for n=1000
        let expected_depth = (n as f64).log2().ceil() as usize;
        assert_eq!(proof.steps.len(), expected_depth);
        assert!(proof.verify(root));
        Ok(())
    }

    #[test]
    fn all_128_leaves_verify_in_power_of_two_tree() -> anyhow::Result<()> {
        let n = 128; // exact power of two — no duplication
        let leaves: Vec<String> = (0..n).map(|i| format!("item_{i}")).collect();
        let refs: Vec<&str> = leaves.iter().map(|s| s.as_str()).collect();
        let tree = MerkleTree::build(&refs);
        let root = tree.get_root_hash().context("missing root")?;

        for leaf_data in &leaves {
            let leaf_hash = hash_leaf(leaf_data.as_bytes());
            let proof = tree.generate_proof(&leaf_hash).context("proof not found")?;
            assert!(proof.verify(root), "failed for {leaf_data}");
        }
        Ok(())
    }

    #[test]
    fn display_formats_as_64_lowercase_hex_chars() {
        let h = hash(b"test");
        let s = h.to_string();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn debug_formats_as_truncated_hex_with_ellipsis() {
        let h = hash(b"test");
        let dbg = format!("{h:?}");
        assert!(dbg.starts_with("Hash("));
        assert!(dbg.ends_with("…)"));
        // Should be much shorter than the full 64-char hex
        assert!(dbg.len() < 30);
    }

    #[test]
    fn hash_survives_bytes_roundtrip() {
        let original = hash(b"hello");
        let reconstructed = Hash::from(*original.as_bytes());
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn as_ref_returns_32_byte_slice() {
        let h = hash(b"data");
        let slice: &[u8] = h.as_ref();
        assert_eq!(slice.len(), 32);
        assert_eq!(slice, h.as_bytes().as_slice());
    }

    #[test]
    fn sha256_of_hello_matches_known_digest() {
        // SHA-256("hello") is a well-known value
        let h = hash(b"hello");
        assert_eq!(
            h.to_string(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn leaf_and_internal_hashes_differ_due_to_domain_prefix() {
        // hash_leaf and hash_pair must produce different results even if the
        // raw byte content happens to be the same length, because they use
        // different domain prefixes (0x00 vs 0x01).
        let data = hash(b"x");
        let as_leaf = hash_leaf(&data.as_bytes().repeat(2));
        let as_pair = hash_pair(&data, &data);
        assert_ne!(as_leaf, as_pair);
    }
}
