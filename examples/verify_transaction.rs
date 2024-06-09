use merkle_tree::{Hash, MerkleTree, MerkleTreeProof};

#[derive(Debug, Clone)]
struct Transaction {
    from: String,
    to: String,
    gas_limit: u64,
    value: u64,
    nonce: u64,
    data: Option<String>
}

#[derive(Debug, Clone)]
struct Block {
    id: String,
    transactions: Vec<Transaction>
}

/* 
 * Like a "projection" of the full node: instead of full blocks only their ids are stored, instead of full MerkleTree only the root of the tree is stored
 */
struct LightNode {
    light_blocks: Vec<(String, Hash)>
}

impl LightNode {
    fn from(full_node: &FullNode) -> LightNode {
        let light_blocks: Vec<(String, Hash)> = full_node.blocks.iter().map(|(block, tree)| {
            (block.id.clone(), tree.get_root().clone())
        }).collect();
        LightNode {
            light_blocks
        }
    }

    fn verify(&self, proof: &MerkleTreeProof, block_id: &str) -> bool {
        if let Some((_, tree_root)) = self.light_blocks.iter().find(|b| b.0 == block_id) {
            merkle_tree::verify_belongs_to_tree(tree_root, proof, merkle_tree::sha256_hash)
        } else {
            false
        }
    }
}

struct FullNode {
    blocks: Vec<(Block, MerkleTree)>
}

impl FullNode {
    fn build_tree_from(block: &Block) -> MerkleTree {
        let transaction_reprs: Vec<String> = block.transactions.iter().map(|transaction| {
            format!("{:?}", transaction)
        }).collect();
        let values: Vec<&str> = transaction_reprs.iter().map(|x| x.as_str()).collect();
        merkle_tree::MerkleTree::build(&values, merkle_tree::sha256_hash)
    }

    fn build_from(blocks: Vec<&Block>) -> FullNode {
        let trees: Vec<MerkleTree> = blocks.iter().map(|block| {
            let tree = FullNode::build_tree_from(block);
            println!("built Merkle tree = {:?}\n", tree);
            tree
        }).collect();
        FullNode {
            blocks: blocks.into_iter().map(|x| (*x).clone()).zip(trees).collect()
        }
    }

    fn generate_proof_for_transaction_in_block(&self, transaction: &Transaction, block_id: &str) -> Option<MerkleTreeProof> {
        if let Some((_, merkle_tree)) = self.blocks.iter().find(|b| b.0.id == block_id) {
            let transaction_hash = merkle_tree::sha256_hash(format!("{:?}", transaction).as_str());
            merkle_tree.generate_proof(transaction_hash)
        } else {
            None
        }
    }
}

/*
 * Ethereum-like example of how a Merkle tree might be used to verify that transactions belong to a block.
 */
fn main() {
    let block_transactions = vec![
        Transaction {
            from: String::from("0x06012c8cf97bead5deae237070f9587f8e7a266d"),
            to: String::from("0xac03bb73b6a9e108530aff4df5077c2b3d481e5a"),
            gas_limit: 10,
            value: 10,
            nonce: 1,
            data: Some(String::from("0x4399584959469569836480213f6"))
        },
        Transaction {
            from: String::from("0x06012c8cf97bead5deae237070f9587f8e7a266d"),
            to: String::from("0xac03bb73b6a9e108530aff4df5077c2b3d481e5a"),
            gas_limit: 10,
            value: 15,
            nonce: 2,
            data: None
        },
        Transaction {
            from: String::from("0x06012c8cf97bead5deae237070f9587f8e7a266d"),
            to: String::from("0xac03bb73b6a9e108530aff4df5077c2b3d481e5a"),
            gas_limit: 10,
            value: 20,
            nonce: 3,
            data: None
        },
        Transaction {
            from: String::from("0x06012c8cf97bead5deae237070f9587f8e7a266d"),
            to: String::from("0xac03bb73b6a9e108530aff4df5077c2b3d481e5a"),
            gas_limit: 10,
            value: 19,
            nonce: 4,
            data: None
        },
        Transaction {
            from: String::from("0x06012c8cf97bead5deae237070f9587f8e7a266d"),
            to: String::from("0xac03bb73b6a9e108530aff4df5077c2b3d481e5a"),
            gas_limit: 10,
            value: 2,
            nonce: 5,
            data: None
        }
    ];
    let block = Block {
        id: String::from("1"),
        transactions: block_transactions
    };
    let other_block_transactions = vec![
        Transaction {
            from: String::from("0xac03bb73b6a9e108530aff4df5077c2b3d481e5a"),
            to: String::from("0x06012c8cf97bead5deae237070f9587f8e7a266d"),
            gas_limit: 10,
            value: 1,
            nonce: 1,
            data: None
        }
    ];
    let other_block = Block {
        id: String::from("2"),
        transactions: other_block_transactions
    };

    /*
     * Constructing the full and light nodes is done gradually by the blockchain infrastructure.
     */
    let full_node = FullNode::build_from(vec![&block]);
    let light_nodes: Vec<LightNode> = (0..5).map(|_| {
        LightNode::from(&full_node)
    }).collect();

    /*
     * Client code which would like to verify the transaction.
     */
    let client_transaction = (&block).transactions.get(2).unwrap();
    let block_id = (&block).id.as_str();
    let client_transaction_proof = full_node.generate_proof_for_transaction_in_block(client_transaction, block_id).unwrap();
    println!("client_transaction_proof = {:?}", client_transaction_proof);

    light_nodes.iter().for_each(|light_node| {
        let verification_result = light_node.verify(&client_transaction_proof, &block_id);
        println!("Verified transaction status on a light node {:?}", verification_result);
    });

    /*
     * Client trying to tamper with the proof: verification will fail
     */
    let other_block_tree = FullNode::build_tree_from(&other_block);
    let other_transaction_hash = merkle_tree::sha256_hash(format!("{:?}", other_block.transactions.get(0).unwrap()).as_str());
    let tampered_client_transaction_proof = other_block_tree.generate_proof(other_transaction_hash).unwrap();
    println!("tampered client_transaction_proof = {:?}\n", tampered_client_transaction_proof);

    light_nodes.iter().for_each(|light_node| {
        let verification_result = light_node.verify(&tampered_client_transaction_proof, &block_id);
        println!("Verified invalid transaction status on a light node {:?}", verification_result);
    });
}