//! LDWM signature verification and generation
#![cfg_attr(not(test), no_std)]
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
            _ => panic!()
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
/// [RFC]: https://www.rfc-editor.org/rfc/rfc8778.html
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