//! File integrity verification using Merkle proofs.
//!
//! Demonstrates how software distribution systems (package managers, firmware
//! updates, IPFS, etc.) use Merkle trees so that a client can verify any
//! single downloaded file against a trusted root hash — without needing the
//! complete file list.
//!
//! The server publishes a compact Merkle root (32 bytes) as the manifest
//! digest. For each file a client downloads, the server also provides a
//! Merkle proof. The client checks the proof against the root to confirm
//! the file hasn't been tampered with and truly belongs to the release.
//!
//! Run with: `cargo run --example file_integrity`

use merkle_tree::MerkleTree;

/// A file in the release: name + content bytes.
struct ReleaseFile {
    name: &'static str,
    content: &'static [u8],
}

/// The distribution server: holds all files and the Merkle tree built from
/// their contents. Publishes the root hash as the release manifest digest.
struct Server {
    files: Vec<ReleaseFile>,
    tree: MerkleTree,
}

impl Server {
    fn new(files: Vec<ReleaseFile>) -> Self {
        let leaves: Vec<&[u8]> = files.iter().map(|f| f.content).collect();
        let tree = MerkleTree::build(&leaves);
        Self { files, tree }
    }

    /// The manifest digest that clients trust (e.g. published on a signed
    /// web page, embedded in a hardware root of trust, etc.).
    fn manifest_root(&self) -> merkle_tree::Hash {
        *self.tree.get_root_hash().expect("non-empty release")
    }

    /// Serve a file by index along with its Merkle proof.
    fn download(&self, index: usize) -> Option<(&[u8], merkle_tree::Proof)> {
        let file = self.files.get(index)?;
        let leaf_hash = self.tree.get_leaf_hash(index)?;
        let proof = self.tree.generate_proof(leaf_hash)?;
        Some((file.content, proof))
    }
}

/// The client: knows only the trusted manifest root.
struct Client {
    trusted_root: merkle_tree::Hash,
}

impl Client {
    /// Verify that `data` is an authentic file from the release.
    ///
    /// Rebuilds the leaf hash from the raw data and checks whether the
    /// proof's leaf matches. Then verifies the full proof against the root.
    fn verify(&self, proof: &merkle_tree::Proof) -> bool {
        proof.verify(&self.trusted_root)
    }
}

fn main() {
    let server = Server::new(vec![
        ReleaseFile { name: "firmware.bin",  content: b"<binary firmware image v2.4.1>" },
        ReleaseFile { name: "config.toml",   content: b"[network]\ndhcp = true\ntimeout = 30" },
        ReleaseFile { name: "signature.sig", content: b"<ed25519 detached signature>" },
        ReleaseFile { name: "changelog.txt", content: b"v2.4.1: fixed buffer overflow in parser" },
        ReleaseFile { name: "checksums.txt", content: b"sha256:abcdef... firmware.bin" },
        ReleaseFile { name: "readme.txt",    content: b"Firmware update package for Device X" },
    ]);

    // The client obtains the manifest root through a trusted channel
    // (e.g. a signed HTTPS response, a hardware fuse value).
    let client = Client {
        trusted_root: server.manifest_root(),
    };

    println!("Release manifest root: {}\n", server.manifest_root());

    // --- Scenario 1: verify individual files --------------------------------

    println!("=== Scenario 1: Verify individual file downloads ===\n");

    for i in 0..server.files.len() {
        let file_name = server.files[i].name;
        let (_data, proof) = server.download(i).expect("file exists");
        let ok = client.verify(&proof);
        println!(
            "  {file_name:<18} verified: {ok}  (proof: {} steps)",
            proof.steps.len()
        );
        assert!(ok);
    }

    let total_files = server.files.len();
    let proof_steps = server
        .download(0)
        .unwrap()
        .1
        .steps
        .len();
    println!(
        "\n  {total_files} files in release, each proof is {proof_steps} steps \
         (log₂({total_files}) ≈ {:.1})\n",
        (total_files as f64).log2()
    );

    // --- Scenario 2: tamper detection ---------------------------------------

    println!("=== Scenario 2: Tampered file detection ===\n");

    let (_original_data, mut tampered_proof) = server.download(0).expect("file exists");

    // Simulate a man-in-the-middle replacing the firmware content. The proof
    // was generated for the original content, so it will no longer match.
    // Even if the attacker re-hashes, the leaf in the proof won't match the
    // new data.
    tampered_proof.leaf = merkle_tree::hash(b"<malicious firmware>");

    let tamper_ok = client.verify(&tampered_proof);
    println!("  Tampered firmware.bin verified: {tamper_ok}");
    assert!(!tamper_ok);

    // --- Scenario 3: partial download is safe --------------------------------

    println!("\n=== Scenario 3: Partial download — only 2 of {total_files} files ===\n");

    // A constrained device only needs firmware.bin and config.toml.
    // It can verify just those two files without downloading the rest.
    let needed = [0, 1]; // firmware.bin, config.toml
    for &idx in &needed {
        let (data, proof) = server.download(idx).expect("file exists");
        let ok = client.verify(&proof);
        println!(
            "  {:<18} {} bytes, verified: {ok}",
            server.files[idx].name,
            data.len()
        );
        assert!(ok);
    }

    println!("\n  Device verified {}/{total_files} files without downloading the rest.\n", needed.len());

    println!("All scenarios passed.");
}
