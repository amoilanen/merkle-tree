use merkle_tree::Hash;

fn main() {

    struct Transaction {
        from: String,
        to: String,
        input: Vec<u8>
    }
    
    struct Block {
        transactions: Vec<Transaction>
    }

    let elements = vec!["a", "b", "c", "d", "e"];
    let hashes: Vec<Hash> = elements.iter().map(|element| merkle_tree::sha256_hash(element)).collect();

    //TODO: Provide an Ethereum-like example where "light node" will call verify_belongs_to_tree and "full node" will call build
    //and will store the full tree, and will provide get_root to be called by a "light node" and generate_proof to be called by the user who will later verify
    //the proof on the "light node"
    //let tree = merkle_tree::MerkleTree::build(hashes);
}