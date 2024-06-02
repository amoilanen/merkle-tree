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

#[derive(PartialEq, Debug)]
enum MerkleTreeDirection {
    Left,
    Right
}

#[derive(PartialEq, Debug)]
pub struct MerkleTreeProofLink {
    hash: Hash,
    direction: Option<MerkleTreeDirection>
}

#[derive(PartialEq, Debug)]
pub struct MerkleTreeProof {
    links: Vec<MerkleTreeProofLink>
}

impl MerkleTreeProof {
    fn compute_root<F>(&self, h: F) -> Option<Hash>
    where F: Fn(&str) -> Hash {
        let mut current_node: Option<Hash> = None;
        for current_link in self.links.iter() {
            current_node = match current_node {
                Some(node_hash) => match current_link.direction {
                    Some(MerkleTreeDirection::Right) => Some(h(&(node_hash.value + &current_link.hash.value))),
                    Some(MerkleTreeDirection::Left) => Some(h(&(current_link.hash.value.clone() + &node_hash.value))),
                    None => None
                },
                None => Some(current_link.hash.clone())
            }
        }
        current_node
    }
}

impl MerkleTree {

    fn build<F>(values: &Vec<&str>, h: F) ->  MerkleTree
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
        let mut proof_links = vec![
            MerkleTreeProofLink {
                hash: hash.clone(),
                direction: None
            }
        ];
        let mut tree_level: usize = self.hashes.len();
        let mut level_hashes = self.hashes.get(tree_level - 1);
        if level_hashes.is_none() {
            return None;
        }
        let mut last_hash_position = level_hashes.unwrap().iter().position(|x| x.value == hash.value);
        if last_hash_position.is_none() {
            return None;
        }
        while tree_level > 1 {
            level_hashes = self.hashes.get(tree_level - 1);
            if level_hashes.is_none() {
                return None;
            }
            if let Some(hash_position) = last_hash_position {
                let direction_to_sibling = if hash_position % 2 == 0 {
                    MerkleTreeDirection::Right
                } else {
                    MerkleTreeDirection::Left
                };
                let sibling_position = if direction_to_sibling == MerkleTreeDirection::Right {
                    hash_position + 1
                } else {
                    hash_position - 1
                };
                let sibling_hash = level_hashes.unwrap().get(sibling_position).unwrap();
                let sibling_proof_link = MerkleTreeProofLink {
                    hash: sibling_hash.clone(),
                    direction: Some(direction_to_sibling)
                };
                proof_links.push(sibling_proof_link);
                last_hash_position = Some(hash_position / 2);
            }
            tree_level -= 1;
        }
        Some(MerkleTreeProof {
            links: proof_links
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

        let tree = MerkleTree::build(&values, |e| Hash { value: String::from(e) });
        assert_eq!(tree.hashes, vec![
            Vec::new()
        ]);
    }

    #[test]
    fn build_merkle_tree_one_hash() {
        let values = vec!["a"];

        let tree = MerkleTree::build(&values, |e| Hash { value: String::from(e) });
        assert_eq!(tree.hashes, vec![
            vec![Hash::new("a")],
        ]);
    }

    #[test]
    fn build_merkle_tree_two_hashes() {
        let values = vec!["a", "b"];

        let tree = MerkleTree::build(&values, |e| Hash { value: String::from(e) });
        assert_eq!(tree.hashes, vec![
            vec![Hash::new("ab")],
            vec![Hash::new("a"), Hash::new("b")],
        ]);
    }

    #[test]
    fn build_merkle_tree_more_hashes() {
        let values = vec!["a", "b", "c", "d", "e", "f", "g", "h"];

        let tree = MerkleTree::build(&values, |e| Hash { value: String::from(e) });
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

        let tree = MerkleTree::build(&values, |e| Hash { value: String::from(e) });
        assert_eq!(tree.hashes, vec![
            vec![Hash::new("abcdeeee")],
            vec![Hash::new("abcd"), Hash::new("eeee")],
            vec![Hash::new("ab"), Hash::new("cd"), Hash::new("ee"), Hash::new("ee")],
            vec![Hash::new("a"), Hash::new("b"), Hash::new("c"), Hash::new("d"), Hash::new("e"), Hash::new("e")],
        ]);
    }

    #[test]
    fn generate_proof_for_hash_present_in_tree() {
        let tree = MerkleTree {
            hashes: vec![
                vec![Hash::new("abcdefgh")],
                vec![Hash::new("abcd"), Hash::new("efgh")],
                vec![Hash::new("ab"), Hash::new("cd"), Hash::new("ef"), Hash::new("gh")],
                vec![Hash::new("a"), Hash::new("b"), Hash::new("c"), Hash::new("d"), Hash::new("e"), Hash::new("f"), Hash::new("g"), Hash::new("h")],
            ]
        };
        assert_eq!(tree.generate_proof(Hash::new("c")), 
            Some(MerkleTreeProof {
                links: vec![
                    MerkleTreeProofLink {
                        hash: Hash::new("c"),
                        direction: None
                    },
                    MerkleTreeProofLink {
                        hash: Hash::new("d"),
                        direction: Some(MerkleTreeDirection::Right)
                    },
                    MerkleTreeProofLink {
                        hash: Hash::new("ab"),
                        direction: Some(MerkleTreeDirection::Left)
                    },
                    MerkleTreeProofLink {
                        hash: Hash::new("efgh"),
                        direction: Some(MerkleTreeDirection::Right)
                    },
                ]
            })
        )
    }

    #[test]
    fn generate_proof_for_hash_absent_from_tree() {
        let tree = MerkleTree {
            hashes: vec![
                vec![Hash::new("ab")],
                vec![Hash::new("a"), Hash::new("b")],
            ]
        };
        assert_eq!(tree.generate_proof(Hash::new("c")), None)
    }

    #[test]
    fn compute_root_from_proof_4_level_tree() {
        let proof = MerkleTreeProof {
            links: vec![
                MerkleTreeProofLink {
                    hash: Hash::new("c"),
                    direction: None
                },
                MerkleTreeProofLink {
                    hash: Hash::new("d"),
                    direction: Some(MerkleTreeDirection::Right)
                },
                MerkleTreeProofLink {
                    hash: Hash::new("ab"),
                    direction: Some(MerkleTreeDirection::Left)
                },
                MerkleTreeProofLink {
                    hash: Hash::new("efgh"),
                    direction: Some(MerkleTreeDirection::Right)
                },
            ]
        };
        assert_eq!(proof.compute_root(|e| Hash { value: String::from(e) }), Some(Hash::new("abcdefgh")))
    }

    #[test]
    fn compute_root_from_proof_2_level_tree() {
        let proof = MerkleTreeProof {
            links: vec![
                MerkleTreeProofLink {
                    hash: Hash::new("a"),
                    direction: None
                },
                MerkleTreeProofLink {
                    hash: Hash::new("b"),
                    direction: Some(MerkleTreeDirection::Right)
                }
            ]
        };
        assert_eq!(proof.compute_root(|e| Hash { value: String::from(e) }), Some(Hash::new("ab")))
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
