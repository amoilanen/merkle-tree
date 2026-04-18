//! File integrity verification using Merkle proofs.
//!
//! Demonstrates how software distribution systems (package managers, firmware
//! updates, IPFS, etc.) use Merkle trees so that a client can verify any
//! single downloaded file against a trusted root hash — without needing the
//! complete file list.
//!
//! A release publishes a compact Merkle root (32 bytes) as the manifest
//! digest. For each file a client downloads, the server also provides a
//! Merkle proof (a short chain of sibling hashes). The client checks the
//! proof against the root to confirm the file hasn't been tampered with
//! and truly belongs to the release.
//!
//! For small releases a signed list of file hashes works just as well.
//! Merkle proofs shine at scale: verifying one file out of a million
//! requires only ~20 hashes (log₂) rather than the full hash list.
//!
//! Run with: `cargo run --example file_integrity`

use anyhow::{Context, Result};
use merkle_tree::MerkleTree;

/// A file in the release: name + content bytes.
struct ReleaseFile {
    name: String,
    content: Vec<u8>,
}

/// A release: all files and the Merkle tree built from their contents.
/// The root hash serves as the release manifest digest.
struct Release {
    files: Vec<ReleaseFile>,
    tree: MerkleTree,
}

impl Release {
    fn new(files: Vec<ReleaseFile>) -> Self {
        let leaves: Vec<&[u8]> = files.iter().map(|f| f.content.as_slice()).collect();
        let tree = MerkleTree::build(&leaves);
        Self { files, tree }
    }

    /// The manifest digest that clients trust (e.g. published on a signed
    /// web page, embedded in a hardware root of trust, etc.).
    fn manifest_root(&self) -> Result<merkle_tree::Hash> {
        self.tree
            .get_root_hash()
            .copied()
            .context("release has no files")
    }
}

/// Simulate downloading a file from a release: returns the file content
/// and its Merkle proof so the client can verify authenticity.
fn download(release: &Release, index: usize) -> Option<(&[u8], merkle_tree::Proof)> {
    let file = release.files.get(index)?;
    let leaf_hash = release.tree.get_leaf_hash(index)?;
    let proof = release.tree.generate_proof(leaf_hash)?;
    Some((&file.content, proof))
}

/// The client: knows only the trusted manifest root.
struct Client {
    trusted_root: merkle_tree::Hash,
}

impl Client {
    /// Verify that `data` is an authentic file from the release.
    ///
    /// Two checks are needed:
    ///
    /// 1. `hash_leaf(data) == proof.leaf` — the downloaded bytes match the
    ///    hash claimed by the proof.  This alone is NOT enough: an attacker
    ///    who controls the download channel could replace both the file and
    ///    the proof's leaf hash, and this check would still pass.
    ///
    /// 2. `proof.verify(&trusted_root)` — the leaf hash chains up through
    ///    sibling hashes to the trusted root, which was obtained through a
    ///    separate secure channel.  This is what actually makes the proof
    ///    unforgeable: the attacker cannot construct a valid chain to the
    ///    root without knowing every other hash in the tree.
    fn verify(&self, data: &[u8], proof: &merkle_tree::Proof) -> bool {
        merkle_tree::hash_leaf(data) == proof.leaf && proof.verify(&self.trusted_root)
    }
}

fn main() -> Result<()> {
    let release = Release::new(vec![
        ReleaseFile { name: "firmware.bin".into(),  content: b"<binary firmware image v2.4.1>".to_vec() },
        ReleaseFile { name: "config.toml".into(),   content: b"[network]\ndhcp = true\ntimeout = 30".to_vec() },
        ReleaseFile { name: "signature.sig".into(), content: b"<ed25519 detached signature>".to_vec() },
        ReleaseFile { name: "changelog.txt".into(), content: b"v2.4.1: fixed buffer overflow in parser".to_vec() },
        ReleaseFile { name: "checksums.txt".into(), content: b"sha256:abcdef... firmware.bin".to_vec() },
        ReleaseFile { name: "readme.txt".into(),    content: b"Firmware update package for Device X".to_vec() },
    ]);

    // The client obtains the manifest root through a trusted channel
    // (e.g. a signed HTTPS response, a hardware fuse value).
    let client = Client {
        trusted_root: release.manifest_root()?,
    };

    println!("Release manifest root: {}\n", release.manifest_root()?);

    let total_files = release.files.len();

    // --- Scenario 1: verify a single file ------------------------------------

    println!("=== Scenario 1: Verify a single downloaded file ===\n");

    // The client downloads only firmware.bin and verifies it against the
    // trusted root — no need to download the other {total_files-1} files.
    let (data, proof) = download(&release, 0)
        .context("firmware.bin not found")?;
    let ok = client.verify(data, &proof);
    println!(
        "  {:<18} verified: {ok}  (proof: {} steps, log₂({total_files}) ≈ {:.1})",
        release.files[0].name,
        proof.steps.len(),
        (total_files as f64).log2()
    );
    assert!(ok);
    println!(
        "\n  Verified 1 of {total_files} files without downloading the rest.\n"
    );

    // --- Scenario 2: tamper detection ---------------------------------------

    println!("=== Scenario 2: Tampered file detection ===\n");

    let (_original_data, proof) = download(&release, 0)
        .context("file at index 0 not found")?;

    // Simulate a man-in-the-middle replacing the firmware content.
    // The client receives tampered bytes but the original proof — the
    // content hash won't match the proof's leaf.
    let tampered_content = b"<malicious firmware>";

    let tamper_ok = client.verify(tampered_content, &proof);
    println!("  Tampered firmware.bin verified: {tamper_ok}");
    assert!(!tamper_ok);

    println!("All scenarios passed.");
    Ok(())
}
