use sha2::{Sha256, Digest};

pub struct Hash {
    value: String
}

pub struct MerkleTree {
    hashes: Vec<Vec<Hash>>
}

enum MerkleTreeDirection {
    Left,
    Right
}

pub struct MerkleTreeProof {
    parts: Vec<(Hash, MerkleTreeDirection)>
}

impl MerkleTreeProof {
    fn compute_root(&self) -> Hash {
        //TODO: Implement
        Hash {
            value: String::from("")
        }
    }
}

impl MerkleTree {

    fn build() -> MerkleTree {
        //TODO: Implement
        MerkleTree {
            hashes: Vec::new()
        }
    }

    fn get_root(&self) -> &Hash {
        self.hashes.get(0).map(|x| x.get(0).unwrap()).unwrap()
    }

    fn generate_proof(&self, hash: Hash) -> Option<MerkleTreeProof> {
        //TODO: Implement
        Some(MerkleTreeProof {
            parts: Vec::new()
        })
    }
}

fn hash(value: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(value);
    Hash { value: String::from(std::str::from_utf8(hasher.finalize().as_slice()).unwrap()) } //TODO: Avoid using "unwrap"
}

pub fn verify_belongs_to_tree(merkle_tree_root: &Hash, merkle_tree_proof: &MerkleTreeProof) -> bool {
    //TODO: Implement
    false
}

fn main() {

    struct Transaction {
        from: String,
        to: String,
        input: Vec<u8>
    }
    
    struct Block {
        transactions: Vec<Transaction>
    }

    //TODO: Provide an Ethereum-like example where "light node" will call verify_belongs_to_tree and "full node" will call build
    //and will store the full tree, and will provide get_root to be called by a "light node" and generate_proof to be called by the user who will later verify
    //the proof on the "light node"

    let elements = vec!["a", "b", "c", "d", "e"];
    let hashes: Vec<Hash> = elements.iter().map(|element| hash(element.as_bytes())).collect();
    println!("Hello, world!");
}

//TODO: Add unit tests
