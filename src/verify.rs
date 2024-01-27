use core::mem;

use crate::{LdwmParams, Signature, Winternitz, SHA256_LEN};

use sha2::{Digest, Sha256};

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

fn gen_ots_candidate<const N: usize>(
    w: Winternitz,
    m: usize,
    msg_hash: &[u8],
    sig: &[u8],
) -> [u8; N] {
    let mut v = [0u8; N];
    v.copy_from_slice(msg_hash);
    let ck = checksum::<N>(w, &v);

    let mask = (1 << usize::from(w)) - 1;
    let mut hasher = Sha256::new();
    let z = sig
        .chunks_exact(m)
        .enumerate()
        .fold(Sha256::new(), |mut z, (i, xi)| {
            let a = mask - coef::<N>(i, w, &v, &ck);
            let mut buf = [0u8; SHA256_LEN];
            buf[0..m].copy_from_slice(xi);
            for _ in 0..a {
                Digest::update(&mut hasher, &buf[0..m]);
                buf = Digest::finalize_reset(&mut hasher).into();
            }
            Digest::update(&mut z, &buf[0..m]);
            z
        });
    v.copy_from_slice(&Digest::finalize(z));
    v
}

fn gen_mts_candidate<const N: usize>(
    h: usize,
    k: usize,
    node_num: usize,
    ots_result: &[u8],
    auth_path: &[u8],
) -> [u8; N] {
    let mut v: [u8; N] = [0u8; N];
    v.copy_from_slice(ots_result);
    (0..h).fold(v, |mut v, lvl| {
        let posn = (node_num / (k.pow(lvl as u32))).rem_euclid(k);
        let mut hasher = Sha256::new();

        let start = N * (lvl * (k - 1));
        let end = start + (N * posn);
        Digest::update(&mut hasher, &auth_path[start..end]);
        Digest::update(&mut hasher, v);

        let start = start + N * posn;
        let end = start + N * (k - posn - 1);
        Digest::update(&mut hasher, &auth_path[start..end]);

        v.copy_from_slice(&Digest::finalize(hasher));
        v
    })
}

/// Verify a signature using the given parameters, signature, key, and message.
///
/// This will construct a candidate key for the One-Time Signature, and will
/// then use that and the authentication path to verify the overall signature,
/// as per the [RFC].
///
/// # Notes
///
/// This only supports SHA256
///
/// If you only have the hash of the message, see [`verify_from_hash`].
/// 
/// This function hashes the message in "one shot"; it does not attempt
/// to perform any kind of buffering. If you need any buffering, you
/// can construct your own hash and use [`verify_from_hash`] instead.
///
/// # Examples
///
/// Using the example in Appendix A of the [RFC].
///
/// ```rust
/// # use ldwm::{LdwmParams, Winternitz, verify::verify, Signature, SHA256_LEN};
/// let params = LdwmParams {
///     w: Winternitz::W4,
///     m: 20,
///     h: 2,
///     k: 4,
/// };
/// let msg = "Hello world!\n".as_bytes();
/// # let key: &'static [u8; SHA256_LEN] = include_bytes!("../resources/example_mts_pub.bin");
/// # let ots = include_bytes!("../resources/example_ots.bin");
/// # let auth_path: &'static [u8] = include_bytes!("../resources/example_auth_path.bin");
/// # let node_num = 0;
/// let sig = Signature { auth_path, ots, node_num };
/// assert!(verify(&params, &sig, key, msg));
/// ```
///
/// [RFC]: https://datatracker.ietf.org/doc/html/draft-mcgrew-hash-sigs-00
pub fn verify(params: &LdwmParams, sig: &Signature, key: &[u8], msg: &[u8]) -> bool {
    let hash: [u8; SHA256_LEN] = <Sha256 as Digest>::digest(msg).into();
    let ots_key: [u8; SHA256_LEN] = gen_ots_candidate(params.w, params.m, &hash, sig.ots);
    let mts_key: [u8; SHA256_LEN] =
        gen_mts_candidate(params.h, params.k, sig.node_num, &ots_key, sig.auth_path);
    mts_key == key
}
/// Verify a signature using the given parameters, signature, key, and message hash.
///
/// This will construct a candidate key for the One-Time Signature, and will
/// then use that and the authentication path to verify the overall signature,
/// as per the [RFC].
///
/// # Notes
///
/// This only supports SHA256.
///
/// If you have the message itself, see [`verify`] for an easier method
///
/// # Examples
///
/// Using the example in Appendix A of the [RFC].
///
/// ```rust
/// # use ldwm::{LdwmParams, Winternitz, verify::verify_from_hash, Signature, SHA256_LEN};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let params = LdwmParams {
///     w: Winternitz::W4,
///     m: 20,
///     h: 2,
///     k: 4,
/// };
/// let msg_hash = hex::decode("0ba904eae8773b70c75333db4de2f3ac45a8ad4ddba1b242f0b3cfc199391dd8")?;
/// # let key: &'static [u8; SHA256_LEN] = include_bytes!("../resources/example_mts_pub.bin");
/// # let ots = include_bytes!("../resources/example_ots.bin");
/// # let auth_path: &'static [u8] = include_bytes!("../resources/example_auth_path.bin");
/// # let node_num = 0;
/// let sig = Signature { auth_path, ots, node_num };
/// assert!(verify_from_hash(&params, &sig, key, &msg_hash));
/// # Ok(())
/// # }
/// ```
///
/// [RFC]: https://datatracker.ietf.org/doc/html/draft-mcgrew-hash-sigs-00
pub fn verify_from_hash(params: &LdwmParams, sig: &Signature, key: &[u8], msg_hash: &[u8]) -> bool {
    let ots_key: [u8; SHA256_LEN] = gen_ots_candidate(params.w, params.m, msg_hash, sig.ots);
    let mts_key: [u8; SHA256_LEN] =
        gen_mts_candidate(params.h, params.k, sig.node_num, &ots_key, sig.auth_path);
    mts_key == key
}

#[cfg(test)]
mod tests {
    use super::{gen_mts_candidate, gen_ots_candidate, verify, verify_from_hash, Winternitz};
    use crate::{LdwmParams, Signature, SHA256_LEN};
    use sha2::{Digest, Sha256};

    #[test]
    fn test_rfc_ots() {
        let w = Winternitz::W4;
        let m = 20;
        let key: &'static [u8] = include_bytes!("../resources/example_ots_pub.bin");
        let sig = include_bytes!("../resources/example_ots.bin");
        let message = "Hello world!\n".as_bytes();
        let hash = <Sha256 as Digest>::digest(message);

        let c: [u8; SHA256_LEN] = gen_ots_candidate(w, m, &hash, sig);
        assert_eq!(&c, key);
    }

    #[test]
    fn test_rfc_mts() {
        let ots: &'static [u8] = include_bytes!("../resources/example_ots_pub.bin");
        let auth_path: &'static [u8] = include_bytes!("../resources/example_auth_path.bin");
        let key: &'static [u8] = include_bytes!("../resources/example_mts_pub.bin");
        let c: [u8; SHA256_LEN] = gen_mts_candidate(2, 4, 0, ots, auth_path);
        assert_eq!(key, c);
    }

    #[test]
    fn test_rfc() {
        let params = LdwmParams {
            w: Winternitz::W4,
            m: 20,
            h: 2,
            k: 4,
        };
        let msg = "Hello world!\n".as_bytes();
        let key: &'static [u8; SHA256_LEN] = include_bytes!("../resources/example_mts_pub.bin");
        let ots = include_bytes!("../resources/example_ots.bin");
        let auth_path: &'static [u8] = include_bytes!("../resources/example_auth_path.bin");
        let node_num = 0;
        let sig = Signature {
            auth_path,
            ots,
            node_num,
        };
        assert!(verify(&params, &sig, key, msg));
    }
    #[test]
    fn test_rfc_with_hash() {
        let params = LdwmParams {
            w: Winternitz::W4,
            m: 20,
            h: 2,
            k: 4,
        };
        let msg = "Hello world!\n".as_bytes();
        let hash: [u8; SHA256_LEN] = <Sha256 as Digest>::digest(msg).into();
        let key: &'static [u8; SHA256_LEN] = include_bytes!("../resources/example_mts_pub.bin");
        let ots = include_bytes!("../resources/example_ots.bin");
        let auth_path: &'static [u8] = include_bytes!("../resources/example_auth_path.bin");
        let node_num = 0;
        let sig = Signature {
            auth_path,
            ots,
            node_num,
        };
        assert!(verify_from_hash(&params, &sig, key, &hash));
    }

    #[test]
    fn test_rfc_failure() {
        let params = LdwmParams {
            w: Winternitz::W4,
            m: 20,
            h: 2,
            k: 4,
        };
        let msg = "Hello world!\n".as_bytes();
        let mut hash: [u8; SHA256_LEN] = <Sha256 as Digest>::digest(msg).into();
        let key: &'static [u8; SHA256_LEN] = include_bytes!("../resources/example_mts_pub.bin");
        let mut ots = include_bytes!("../resources/example_ots.bin").to_vec();
        let mut auth_path = include_bytes!("../resources/example_auth_path.bin").to_vec();
        let node_num = 0;
        let sig = Signature {
            auth_path: &auth_path,
            ots: &ots,
            node_num,
        };
        // Wrong hash
        hash[0] = !hash[0];
        assert!(!verify_from_hash(&params, &sig, key, &hash));
        hash[0] = !hash[0];
        ots[0] = !ots[0];
        let sig = Signature {
            auth_path: &auth_path,
            ots: &ots,
            node_num,
        };
        assert!(!verify_from_hash(&params, &sig, key, &hash));
        ots[0] = !ots[0];
        auth_path[0] = !auth_path[0];
        let sig = Signature {
            auth_path: &auth_path,
            ots: &ots,
            node_num,
        };
        assert!(!verify_from_hash(&params, &sig, key, &hash));
        auth_path[0] = !auth_path[0];
        let node_num = 1;
        let sig = Signature {
            auth_path: &auth_path,
            ots: &ots,
            node_num,
        };
        assert!(!verify_from_hash(&params, &sig, key, &hash));
        let node_num = 0;
        let sig = Signature {
            auth_path: &auth_path,
            ots: &ots,
            node_num,
        };
        assert!(verify_from_hash(&params, &sig, key, &hash))
    }
}
