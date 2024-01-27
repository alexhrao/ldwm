# LDWM

LDWM implementation in pure Rust. This library currently provides
__verification__ support; eventually, signing support will also
be added.

Verification is `#no_std` compatible.

## Example

```rust
use ldwm::{LdwmParams, Winternitz, verify::verify, Signature, SHA256_LEN};
let params = LdwmParams {
    w: Winternitz::W4,
    m: 20,
    h: 2,
    k: 4,
};
let msg = "Hello world!\n".as_bytes();
// `auth_path`, `ots`, and `node_num` as from the RFC
let sig = Signature { auth_path, ots, node_num };
assert!(verify(&params, &sig, key, msg));
```