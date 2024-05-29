use std::thread::current;

use sha2::{Sha256, Digest};

#[derive(PartialEq, Debug, Clone)]
pub struct Hash {
    value: String
}

impl Hash {
    fn new(value: &str) -> Hash {
        Hash { value: String::from(value) }
    }
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

    fn build<F>(h: F, values: &Vec<&str>) ->  MerkleTree
    where F: Fn(&str) -> Hash {
        let hashes: Vec<Hash> = values.iter().map(|x| h(x)).collect();
        let mut tree: Vec<Vec<Hash>> = Vec::new();
        let mut current_level = hashes;
        while current_level.len() > 1 {
            if current_level.len() % 2 != 0 {
                let last = current_level.last().unwrap().clone();
                current_level.push(last);
            }
            tree.push(current_level.clone());

            let updated_level: Vec<Hash> = current_level.iter().enumerate().step_by(2).map(|(idx, current_hash)| {
                let neighbor_hash = current_level.get(idx + 1).unwrap();
                let combined_hash = h(&format!("{}{}", current_hash.value, neighbor_hash.value));
                combined_hash
            }).collect();
            current_level = updated_level;
        }
        tree.push(current_level.clone());
        tree.reverse();
        MerkleTree {
            hashes: tree
        }
    }

    fn get_root(&self) -> &Hash {
        //TODO: Avoid unwrap
        self.hashes.get(0).map(|x| x.get(0).unwrap()).unwrap()
    }

    fn generate_proof(&self, hash: Hash) -> Option<MerkleTreeProof> {
        //TODO: Implement
        Some(MerkleTreeProof {
            parts: Vec::new()
        })
    }
}

fn sha256_hash(value: &str) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    Hash { value: String::from(std::str::from_utf8(hasher.finalize().as_slice()).unwrap()) } //TODO: Avoid using "unwrap"
}

pub fn verify_belongs_to_tree(merkle_tree_root: &Hash, merkle_tree_proof: &MerkleTreeProof) -> bool {
    //TODO: Implement
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_merkle_tree_zero_hashes() {
        let values: Vec<&str> = Vec::new();

        let tree = MerkleTree::build(|e| Hash { value: String::from(e) }, &values);
        assert_eq!(tree.hashes, vec![
            Vec::new()
        ]);
    }

    #[test]
    fn build_merkle_tree_one_hash() {
        let values = vec!["a"];

        let tree = MerkleTree::build(|e| Hash { value: String::from(e) }, &values);
        assert_eq!(tree.hashes, vec![
            vec![Hash::new("a")],
        ]);
    }

    #[test]
    fn build_merkle_tree_two_hashes() {
        let values = vec!["a", "b"];

        let tree = MerkleTree::build(|e| Hash { value: String::from(e) }, &values);
        assert_eq!(tree.hashes, vec![
            vec![Hash::new("ab")],
            vec![Hash::new("a"), Hash::new("b")],
        ]);
    }

    #[test]
    fn build_merkle_tree_more_hashes() {
        let values = vec!["a", "b", "c", "d", "e", "f", "g", "h"];

        let tree = MerkleTree::build(|e| Hash { value: String::from(e) }, &values);
        assert_eq!(tree.hashes, vec![
            vec![Hash::new("abcdefgh")],
            vec![Hash::new("abcd"), Hash::new("efgh")],
            vec![Hash::new("ab"), Hash::new("cd"), Hash::new("ef"), Hash::new("gh")],
            vec![Hash::new("a"), Hash::new("b"), Hash::new("c"), Hash::new("d"), Hash::new("e"), Hash::new("f"), Hash::new("g"), Hash::new("h")],
        ]);
    }

    #[test]
    fn build_merkle_tree_more_hashes_not_a_degree_of_two() {
        let values = vec!["a", "b", "c", "d", "e"];

        let tree = MerkleTree::build(|e| Hash { value: String::from(e) }, &values);
        assert_eq!(tree.hashes, vec![
            vec![Hash::new("abcdeeee")],
            vec![Hash::new("abcd"), Hash::new("eeee")],
            vec![Hash::new("ab"), Hash::new("cd"), Hash::new("ee"), Hash::new("ee")],
            vec![Hash::new("a"), Hash::new("b"), Hash::new("c"), Hash::new("d"), Hash::new("e"), Hash::new("e")],
        ]);
    }
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
    let hashes: Vec<Hash> = elements.iter().map(|element| sha256_hash(element)).collect();
    println!("Hello, world!");
}
