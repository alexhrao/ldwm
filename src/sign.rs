use rand::RngCore;
#[cfg(feature = "rayon")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::{
    checksum, coef, AuthTreeNode, GeneratedSignature, LdwmParams, LdwmPrivateKey, SHA256_LEN,
};

fn gen_ots_private_key(params: &LdwmParams) -> Vec<u8> {
    let w: u32 = params.w.into();
    let u = 8 * (SHA256_LEN as u32) / w;
    let v = u.ilog2().div_ceil(w);
    let p = (u + v) as usize;
    let mut out = vec![0u8; SHA256_LEN * p];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

fn gen_ots_public_key(prv: &[u8], params: &LdwmParams) -> [u8; SHA256_LEN] {
    let mut hasher = Sha256::new();
    let LdwmParams { w, m, .. } = *params;
    let w: usize = w.into();
    let hash_count = (1 << w) - 1;
    let z = prv
        .chunks_exact(SHA256_LEN)
        .fold(Sha256::new(), |mut z, xi| {
            let mut buf = [0u8; SHA256_LEN];
            buf[0..m].copy_from_slice(&xi[0..m]);
            for _ in 0..hash_count {
                Digest::update(&mut hasher, &buf[0..m]);
                buf = Digest::finalize_reset(&mut hasher).into();
            }
            Digest::update(&mut z, &buf[0..m]);
            z
        });
    Digest::finalize(z).into()
}

fn sign_ots_hash(prv: &[u8], msg_hash: &[u8], params: &LdwmParams) -> Vec<u8> {
    // TODO: Return error if hash is wrong length
    let msg_hash: &[u8; SHA256_LEN] = msg_hash.try_into().unwrap();
    let LdwmParams { w, m, .. } = *params;
    let ck = checksum::<SHA256_LEN>(w, msg_hash);
    let mut hasher = Sha256::new();
    prv.chunks_exact(SHA256_LEN)
        .enumerate()
        .flat_map(|(i, xi)| {
            let a = coef::<SHA256_LEN>(i, params.w, msg_hash, &ck);
            let mut buf = xi.to_vec();
            buf.resize(m, 0);
            for _ in 0..a {
                Digest::update(&mut hasher, &buf);
                buf.copy_from_slice(&Digest::finalize_reset(&mut hasher)[0..m]);
            }
            buf
        })
        .collect()
}

impl LdwmPrivateKey {
    /// Creates a new LDWM Private Key, using the given parameters
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ldwm::{LdwmPrivateKey, LdwmParams, Winternitz};
    /// let params = LdwmParams { h: 2, k: 4, m: 20, w: Winternitz::W4 };
    /// let private_key = LdwmPrivateKey::new(&params);
    /// ```
    pub fn new(params: &LdwmParams) -> Self {
        let num_keys = params.k.pow(params.h as u32);
        let ots_keys: Vec<_> = (0..num_keys).map(|_| gen_ots_private_key(params)).collect();
        let tree = Self::generate_auth_tree(&ots_keys, params);
        LdwmPrivateKey {
            ots_keys,
            node_num: 0,
            params: *params,
            tree,
        }
    }

    /// Creates a new private key in parallel
    ///
    /// On capable machines, this can be faster than [`LdwmPrivateKey::new`].
    ///
    /// # Examples
    /// ```rust
    /// # use ldwm::{LdwmPrivateKey, LdwmParams, Winternitz};
    /// let params = LdwmParams { h: 2, k: 4, m: 20, w: Winternitz::W4 };
    /// let private_key = LdwmPrivateKey::par_new(&params);
    /// ```
    #[cfg(feature = "rayon")]
    pub fn par_new(params: &LdwmParams) -> Self {
        let num_keys = params.k.pow(params.h as u32);
        let ots_keys: Vec<_> = (0..num_keys)
            .into_par_iter()
            .map(|_| gen_ots_private_key(params))
            .collect();
        let tree = Self::generate_auth_tree(&ots_keys, params);
        LdwmPrivateKey {
            ots_keys,
            node_num: 0,
            params: *params,
            tree,
        }
    }

    fn generate_auth_tree(ots_keys: &[Vec<u8>], params: &LdwmParams) -> AuthTreeNode {
        // Start at the children, which are my OTS keys
        let mut level: Vec<_> = ots_keys
            .iter()
            .map(|k| AuthTreeNode {
                value: gen_ots_public_key(k, params).to_vec(),
                children: vec![],
            })
            .collect();
        while level.len() > 1 {
            let mut next_level = vec![];
            while !level.is_empty() {
                let children: Vec<_> = level.drain(0..params.k).collect();
                let value = Digest::finalize(children.iter().fold(Sha256::new(), |mut h, c| {
                    Digest::update(&mut h, &c.value);
                    h
                }))
                .to_vec();
                next_level.push(AuthTreeNode { value, children });
            }
            level = next_level;
        }
        level.pop().unwrap()
    }
    /// Signs a message, incrementing internal state in the process
    ///
    /// If you only have access to the hash, or otherwise want finer-grained
    /// control over the hashing process, see [`sign_hash`](`LdwmPrivateKey::sign_hash`)
    /// instead.
    ///
    /// # Examples
    ///
    /// Sign a message with a newly-minted private key. Note that this example
    /// uses a non-standard parameter set for efficiency.
    ///
    /// ```rust
    /// # use ldwm::{LdwmPrivateKey, LdwmParams, Winternitz};
    /// let params = LdwmParams { h: 2, k: 4, m: 20, w: Winternitz::W4 };
    /// let mut key = LdwmPrivateKey::new(&params);
    /// let msg = "Hello world!\n".as_bytes();
    /// let sig = key.sign(msg);
    /// ```
    pub fn sign(&mut self, msg: &[u8]) -> GeneratedSignature {
        let hash: [u8; SHA256_LEN] = <Sha256 as Digest>::digest(msg).into();
        self.sign_hash(&hash)
    }
    /// Signs a message hash, incrementing internal state in the process
    ///
    /// If you just want to sign a message, see the convenience method
    /// [`sign`](`LdwmPrivateKey::sign`) instead.
    ///
    /// # Panics
    ///
    /// This will panic if the hash is not the length of a SHA256 hash; see
    /// [`SHA256_LEN`].
    ///
    /// # Examples
    ///
    /// Sign a message with a newly-minted private key. Note that this example
    /// uses a non-standard parameter set for efficiency.
    ///
    /// ```rust
    /// # use ldwm::{LdwmPrivateKey, LdwmParams, Winternitz, SHA256_LEN};
    /// # use sha2::{Sha256, Digest};
    /// let params = LdwmParams { h: 2, k: 4, m: 20, w: Winternitz::W4 };
    /// let mut key = LdwmPrivateKey::new(&params);
    /// let hash: [u8; SHA256_LEN] = <Sha256 as Digest>::digest("Hello world!\n").into();
    /// let sig = key.sign_hash(&hash);
    /// ```
    pub fn sign_hash(&mut self, msg_hash: &[u8]) -> GeneratedSignature {
        assert_eq!(msg_hash.len(), SHA256_LEN);
        let node_num = self.node_num;
        self.node_num += 1;
        let ots_prv = &self.ots_keys[node_num];
        let ots = sign_ots_hash(ots_prv, msg_hash, &self.params);

        let mut idx = vec![];
        let mut i = node_num;
        for _ in 0..self.params.h {
            idx.push(i % self.params.k);
            i /= self.params.k;
        }
        idx.reverse();

        let mut node = &self.tree;
        let mut auth_path: Vec<Vec<u8>> = vec![];
        for i in idx {
            let mut level: Vec<u8> = vec![];
            for (c, child) in node.children.iter().enumerate() {
                if c == i {
                    continue;
                }
                level.extend(&child.value);
            }
            auth_path.push(level);
            node = &node.children[i];
        }
        let auth_path = auth_path.into_iter().rev().flatten().collect();
        GeneratedSignature {
            auth_path,
            node_num,
            ots,
        }
    }
    /// Get the public key for this LDWM Private Key
    ///
    /// # Examples
    ///
    /// Get a public key for a newly-minted private key. This key can be given
    /// freely, and is necessary for verification
    /// ```rust
    /// # use ldwm::{LdwmPrivateKey, LdwmParams, Winternitz, verify::verify};
    /// let params = LdwmParams { h: 2, k: 4, m: 20, w: Winternitz::W4 };
    /// let mut key = LdwmPrivateKey::new(&params);
    /// let msg = "Hello world!\n".as_bytes();
    /// let sig = key.sign(msg);
    /// // Now, let's verify it
    /// let pub_key = key.public_key();
    /// // Verification requires a borrowed signature; we have an owned one.
    /// assert!(verify(&params, &sig.as_borrowed(), &pub_key, msg));
    ///
    /// ```
    pub fn public_key(&self) -> Vec<u8> {
        self.tree.value.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::{
        verify::{gen_ots_candidate, verify},
        LdwmParams, LdwmPrivateKey, Winternitz, SHA256_LEN,
    };

    use super::{gen_ots_private_key, gen_ots_public_key, sign_ots_hash};

    #[test]
    fn test_ots() {
        let params = LdwmParams {
            w: Winternitz::W4,
            m: 20,
            h: 2,
            k: 4,
        };
        let msg_hash: [u8; SHA256_LEN] = <Sha256 as Digest>::digest("Hello world!\n").into();
        let prv = gen_ots_private_key(&params);
        let sig = sign_ots_hash(&prv, &msg_hash, &params);
        let pb = gen_ots_public_key(&prv, &params);
        let pb2: [u8; SHA256_LEN] = gen_ots_candidate(params.w, params.m, &msg_hash, &sig);
        assert_eq!(pb, pb2);
    }

    #[test]
    fn test_roundtrip() {
        let params = LdwmParams {
            h: 2,
            k: 4,
            m: 20,
            w: Winternitz::W4,
        };
        let mut key = LdwmPrivateKey::new(&params);
        let msg = "Hello world!\n".as_bytes();
        let sig = key.sign(msg);
        // Now, let's verify it
        let pub_key = key.public_key();
        // Verification requires a borrowed signature; we have an owned one.
        assert!(verify(&params, &sig.as_borrowed(), &pub_key, msg));
    }
}
