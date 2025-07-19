use crate::crypto::hash::HashFunction;

#[derive(Debug, Clone,)]
pub struct MerkleTree {
    nodes: Vec<Vec<Vec<u8,>,>,>,
    height: usize,
}

impl MerkleTree {
    pub fn build<H: HashFunction,>(leaves: &[Vec<u8,>], public_seed: &[u8], hasher: &H,) -> Self {
        let height = (leaves.len() as f64).log2().ceil() as usize;
        let num_leaves = 1 << height;
        assert_eq!(leaves.len(), num_leaves, "Number of leaves must be 2^height");

        let mut nodes: Vec<Vec<Vec<u8,>,>,> = Vec::with_capacity(height + 1,);
        for i in 0..=height {
            nodes.push(vec![vec![0u8; hasher.output_size()]; num_leaves >> i],);
        }

        for (i, leaf,) in leaves.iter().enumerate() {
            nodes[0][i] = leaf.clone();
        }

        for h in 0..height {
            let num_nodes = nodes[h].len() / 2;
            for i in 0..num_nodes {
                let left = &nodes[h][2 * i];
                let right = &nodes[h][2 * i + 1];
                nodes[h + 1][i] = hash_tree_node(hasher, public_seed, h, i, left, right,);
            }
        }

        MerkleTree { nodes, height, }
    }

    pub fn root(&self,) -> &[u8] {
        &self.nodes[self.height][0]
    }

    pub fn height(&self,) -> usize {
        self.height
    }

    pub fn authentication_path(&self, leaf_index: usize,) -> AuthPath {
        let mut auth_nodes = Vec::new();
        let mut index = leaf_index;

        for h in 0..self.height {
            let sibling_index = index ^ 1;
            auth_nodes.push(self.nodes[h][sibling_index].clone(),);
            index >>= 1;
        }

        AuthPath::new(auth_nodes,)
    }
}

#[derive(Debug, Clone,)]
pub struct AuthPath {
    nodes: Vec<Vec<u8,>,>,
}

impl AuthPath {
    pub fn new(nodes: Vec<Vec<u8,>,>,) -> Self {
        AuthPath { nodes, }
    }

    pub fn nodes(&self,) -> &[Vec<u8,>] {
        &self.nodes
    }

    pub fn compute_root<H: HashFunction,>(
        &self,
        leaf: &[u8],
        leaf_index: usize,
        public_seed: &[u8],
        hasher: &H,
    ) -> Vec<u8,> {
        let mut node = leaf.to_vec();
        let mut index = leaf_index;

        for (h, auth_node,) in self.nodes.iter().enumerate() {
            let (left, right,) =
                if index & 1 == 0 { (&node, auth_node,) } else { (auth_node, &node,) };

            node = hash_tree_node(hasher, public_seed, h, index >> 1, left, right,);
            index >>= 1;
        }

        node
    }
}

fn hash_tree_node<H: HashFunction,>(
    hasher: &H,
    public_seed: &[u8],
    height: usize,
    index: usize,
    left: &[u8],
    right: &[u8],
) -> Vec<u8,> {
    let mut data = Vec::new();
    data.push(0x01,);
    data.extend_from_slice(public_seed,);
    data.extend_from_slice(&(height as u32).to_be_bytes(),);
    data.extend_from_slice(&(index as u32).to_be_bytes(),);
    data.extend_from_slice(left,);
    data.extend_from_slice(right,);

    hasher.hash(&data,)
}
