//! LDWM signature verification and generation
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

use core::{fmt::Debug, mem};
#[cfg(feature = "std")]
use std::io;
#[cfg(feature = "sign")]
mod sign;
/// Verification Support
#[cfg(feature = "verify")]
pub mod verify;
/// The length of a SHA256 Hash
pub const SHA256_LEN: usize = 32;

/// Winternitz Parameter
///
/// This represents how many bits per "word"
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Winternitz {
    /// Reserved, do not use
    Reserved = 0x0,
    /// A W parameter of 1; each word is 1 bit
    W1,
    /// A W parameter of 2; each word is 2 bits
    W2,
    /// A W parameter of 4; each word is 4 bits
    W4,
    /// A W parameter of 8; each word is 8 bits
    W8,
}

impl From<Winternitz> for u32 {
    fn from(value: Winternitz) -> Self {
        match value {
            Winternitz::Reserved => 0,
            Winternitz::W1 => 1,
            Winternitz::W2 => 2,
            Winternitz::W4 => 4,
            Winternitz::W8 => 8,
        }
    }
}
impl From<u32> for Winternitz {
    fn from(value: u32) -> Self {
        match value {
            0 => Winternitz::Reserved,
            1 => Winternitz::W1,
            2 => Winternitz::W2,
            4 => Winternitz::W4,
            8 => Winternitz::W8,
            _ => panic!(),
        }
    }
}

impl From<Winternitz> for usize {
    fn from(value: Winternitz) -> Self {
        match value {
            Winternitz::Reserved => 0,
            Winternitz::W1 => 1,
            Winternitz::W2 => 2,
            Winternitz::W4 => 4,
            Winternitz::W8 => 8,
        }
    }
}

impl From<u8> for Winternitz {
    fn from(value: u8) -> Self {
        match value {
            0 => Winternitz::Reserved,
            1 => Winternitz::W1,
            2 => Winternitz::W2,
            4 => Winternitz::W4,
            8 => Winternitz::W8,
            _ => panic!(),
        }
    }
}

/// LDWM Signature Parameters
///
/// Note that this library assumes SHA256 (i.e., `n` = 32);
/// future iterations may relax this constraint.
///
/// For more information, see the [RFC].
///
/// [RFC]: https://datatracker.ietf.org/doc/html/draft-mcgrew-hash-sigs-00
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LdwmParams {
    /// The Winternitz parameter
    pub w: Winternitz,
    /// The `m` parameter; this is how many bytes we should
    /// collect from the hash result.
    ///
    /// For example, if `m = 20`, each hash from SHA256 produces
    /// 32 bytes, and we then take the left-most 20 bytes
    pub m: usize,
    /// The `k` parameter; this represents how many leaves
    /// per node in the tree that we will have
    pub k: usize,
    /// The height of the tree
    pub h: usize,
}

impl LdwmParams {
    #[cfg(feature = "sign")]
    fn serialize<F>(&self, fd: &mut F) -> io::Result<()>
    where
        F: io::Write,
    {
        fd.write_all(&(self.h as u32).to_be_bytes())?;
        fd.write_all(&(self.k as u32).to_be_bytes())?;
        fd.write_all(&(self.m as u32).to_be_bytes())?;
        fd.write_all(&(u32::from(self.w)).to_be_bytes())
    }
    #[cfg(feature = "sign")]
    fn deserialize<F>(fd: &mut F) -> io::Result<Self>
    where
        F: io::Read,
    {
        let mut buf = 0u32.to_be_bytes();
        fd.read_exact(&mut buf)?;
        let h = u32::from_be_bytes(buf) as usize;
        fd.read_exact(&mut buf)?;
        let k = u32::from_be_bytes(buf) as usize;
        fd.read_exact(&mut buf)?;
        let m = u32::from_be_bytes(buf) as usize;
        fd.read_exact(&mut buf)?;
        let w = u32::from_be_bytes(buf);
        let w = Winternitz::from(w);
        Ok(Self { h, k, m, w })
    }
}

/// A Single LDWM-based signature
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature<'a> {
    /// The authentication path, as a sequence of bytes
    pub auth_path: &'a [u8],
    /// The zero-based node index for the leaf that was
    /// used to create the one-time signature
    pub node_num: usize,
    /// The LDWM-based One-Time Signature, as a sequence
    /// of bytes
    pub ots: &'a [u8],
}

#[cfg(feature = "sign")]
/// A Generated signature that owns its data
///
/// This is made available by the "sign" feature
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GeneratedSignature {
    /// The authentication path, including the (k-1) nodes that will be needed
    /// for verification.
    pub auth_path: Vec<u8>,
    /// The node (leaf) number
    pub node_num: usize,
    /// The One-time Signature
    pub ots: Vec<u8>,
}
#[cfg(feature = "sign")]
impl GeneratedSignature {
    /// Views this signature as a borrowed one.
    ///
    /// This is useful if you're verifying this signature
    /// immediately after generating it.
    pub fn as_borrowed(&self) -> Signature<'_> {
        Signature {
            auth_path: &self.auth_path,
            node_num: self.node_num,
            ots: &self.ots,
        }
    }
}
#[cfg(feature = "sign")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AuthTreeNode {
    value: Vec<u8>,
    children: Vec<AuthTreeNode>,
}
#[cfg(feature = "sign")]
impl AuthTreeNode {
    fn serialize<F>(&self, fd: &mut F) -> io::Result<()>
    where
        F: io::Write,
    {
        fd.write_all(&self.value)?;
        for c in &self.children {
            c.serialize(fd)?;
        }
        Ok(())
    }
    fn deserialize<F>(lvl: usize, k: usize, fd: &mut F) -> io::Result<Self>
    where
        F: io::Read,
    {
        let mut node = AuthTreeNode {
            value: vec![0u8; SHA256_LEN],
            children: Vec::with_capacity(k),
        };
        fd.read_exact(&mut node.value)?;
        if lvl > 0 {
            for _ in 0..k {
                node.children
                    .push(AuthTreeNode::deserialize(lvl - 1, k, fd)?);
            }
        }
        Ok(node)
    }
}
#[cfg(feature = "sign")]
/// LDWM Private Key
///
/// # Notes
///
/// This struct intentionally does **not** implement the [`Clone`]
/// trait, because cloning a private key should never be done. Once
/// a private OTS key has been used, it can **never** be used again,
/// because each time it is used, it leaks part of the private key.
/// Multiple uses leads to a deterioration in security, to the point
/// where it's been completely compromised.
///
/// To protect against this, a signature is a _mutating_ process;
/// an internal counter is updated. It is also for this reason that internals
/// are not, and will never be, exposed, and why Debug
///
/// This will only be available if the "sign" feature is enabled
pub struct LdwmPrivateKey {
    params: LdwmParams,
    ots_keys: Vec<Vec<u8>>,
    node_num: usize,
    tree: AuthTreeNode,
}
#[cfg(feature = "sign")]
impl LdwmPrivateKey {
    /// Serializes this key into a stream, consuming it in the process
    ///
    /// This consumes the key because, once serialized, it
    /// should not be used; otherwise, the serialized
    /// key will become "out of sync" with the one in memory.
    /// As detailed elsewhere, this would undercut the security
    /// and integrity of the signature.
    ///
    /// # Notes
    ///
    /// The serialization format is intentionally omitted from
    /// this API; while it is unlikely to change, there should be
    /// no reason for a consumer other than this code to attempt
    /// deserialization, for the simple reason that it might imply
    /// multiple, out-of-sync keys in existence.
    ///
    /// Note that the output binary can be quite large; on the order of
    /// MB. Be sure you have space on the order of (h^k)*w bytes.
    ///
    /// # Examples
    ///
    /// Serialize a key offline, after performing a signature
    /// ```rust
    /// # use ldwm::{LdwmPrivateKey, LdwmParams, Winternitz, verify::verify};
    /// # use std::{io, fs};
    /// let params = LdwmParams { h: 2, k: 4, m: 20, w: Winternitz::W4 };
    /// let mut key = LdwmPrivateKey::new(&params);
    /// let msg = "Hello world!\n".as_bytes();
    /// let sig = key.sign(msg);
    /// // We're done with this key for now, let's save it to a file
    /// // `fd` is a file descriptor opened for writing
    /// # let mut fd = vec![];
    /// key.serialize(&mut fd)?;
    /// # io::Result::Ok(())
    /// ```
    pub fn serialize<F>(self, fd: &mut F) -> io::Result<()>
    where
        F: io::Write,
    {
        fd.write_all(&(self.node_num as u32).to_be_bytes())?;
        self.params.serialize(fd)?;
        let ots_keys: Vec<_> = self.ots_keys.into_iter().flatten().collect();
        fd.write_all(&ots_keys)?;
        self.tree.serialize(fd)
    }
    /// Deserializes a private LDWM Key from a reader
    ///
    /// # Notes
    ///
    /// As detailed in the docs for [`serialize`](`LdwmPrivateKey::serialize`),
    /// the serialization format is intentionally left vague.
    ///
    pub fn deserialize<F>(fd: &mut F) -> io::Result<Self>
    where
        F: io::Read,
    {
        let mut buf = 0u32.to_be_bytes();
        fd.read_exact(&mut buf)?;
        let node_num = u32::from_be_bytes(buf) as usize;
        let params = LdwmParams::deserialize(fd)?;
        let w: u32 = params.w.into();
        let u = 8 * (SHA256_LEN as u32) / w;
        let v = u.ilog2().div_ceil(w);
        let p = (u + v) as usize;
        let num_keys = params.k.pow(params.h as u32);
        let mut ots_keys = Vec::with_capacity(num_keys);
        for _ in 0..num_keys {
            let mut ots_key = vec![0u8; SHA256_LEN * p];
            fd.read_exact(&mut ots_key)?;
            ots_keys.push(ots_key);
        }
        let tree = AuthTreeNode::deserialize(params.h, params.k, fd)?;
        Ok(Self {
            node_num,
            params,
            ots_keys,
            tree,
        })
    }
}
#[cfg(feature = "sign")]
impl Debug for LdwmPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "LDWM Private Key {{ num_keys: {} }}",
            self.ots_keys.len()
        )
    }
}

fn coef<const N: usize>(i: usize, w: Winternitz, s: &[u8; N], ck: &[u8; 2]) -> u8 {
    let w: usize = w.into();
    let max: usize = Winternitz::W8.into();
    let mask: u8 = (1 << w) - 1;
    let shift = max - (w * (i % (max / w)) + w);
    let idx = (i * w) / max;
    if idx >= N {
        mask & (ck[idx - N] >> shift)
    } else {
        mask & (s[(i * w) / max] >> shift)
    }
}

fn checksum<const N: usize>(w: Winternitz, s: &[u8; N]) -> [u8; mem::size_of::<u16>()] {
    let u: usize = N * 8 / usize::from(w);
    let mask = (1 << usize::from(w)) - 1;
    let ck = (0..u)
        .map(|i| mask - coef(i, w, s, &[0u8; 2]) as u16)
        .sum::<u16>();
    let shift = ck.leading_zeros() - (ck.leading_zeros() % 4);

    (ck << shift).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use core::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    use crate::{LdwmParams, LdwmPrivateKey};

    #[test]
    fn test_serialization_roundtrip() {
        let p1 = LdwmParams {
            h: 2,
            k: 4,
            m: 20,
            w: crate::Winternitz::W4,
        };
        fn hash_key(key: &LdwmPrivateKey) -> u64 {
            let mut hasher = DefaultHasher::new();
            key.params.hash(&mut hasher);
            key.node_num.hash(&mut hasher);
            key.ots_keys.hash(&mut hasher);
            key.tree.hash(&mut hasher);
            hasher.finish()
        }
        let k1 = LdwmPrivateKey::new(&p1);
        let k1_hash = hash_key(&k1);
        let mut buffer = Vec::new();
        k1.serialize(&mut buffer).unwrap();
        let k2 = LdwmPrivateKey::deserialize(&mut buffer.as_slice()).unwrap();
        let k2_hash = hash_key(&k2);
        assert_eq!(k1_hash, k2_hash);
    }
}
