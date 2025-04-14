> [!CAUTION]
> This library is a proof-of-concept. It probably contains bugs, maybe serious ones undermining security.

> [!WARNING]
> Pseudonymous Signatures as implemented rely on secure hardware storage of group member keys. Any pair of member keys will enable attackers to derive the private key.

# pss-rs

`pss-rs` is a Rust library implementing Pseudonymous Signatures as specified in [BSI TR-03110: Technical Guideline Advanced Security Mechanisms for Machine Readable Travel Documents and eIDAS Token](https://www.bsi.bund.de/dok/TR-03110-en).

It provides interfaces to use it with popular Rust crypto libraries, i.e. RustCrypto/elliptic-curve or ark.

## Example
```rust
type C = PssSecp256k1;

let mut group_manager = EccGroupManager::new(None);
let icc: EccIcc<C> = group_manager.new_icc();
let sector = group_manager.new_sector(false);
let signer = icc.signer(&sector, id1, id2);
let signature = signer.sign(SIGN_MESSAGE);
```

## Keygen

This repo features a small command line tool (`pss-keygen`), which is able to generate and export key material.
Call `pss-keygen --help` to get an overview over the valid command line options.

## WASM

This repo provides wasm bindings in `pss-rs-wasm`.
You can use it like this:

```js
import { default as init, Algorithm, JsGroupManagerPrivateKey } from "./pkg/pss_rs_wasm.js";

async function main() {
    const pssrs = await init();
    const alg = Algorithm.Secp256k1;
    const gm = new JsGroupManagerPrivateKey(alg);
    const gpk = gm.public_key(alg);
    const sector = gm.new_sector(alg, false);
    const icc = gm.new_icc(alg);
    const sig10 = icc.sign(alg, gpk, sector, true, false, [0, 1, 2]);
    console.log("Sig ok?", gpk.check_signature(alg, sector, sig10, [0, 1, 2]));
}
```

# Solidity

You can find Solidity contracts to check PSS signatures in `pss-sol`.
Furthermore, you can use `pss-keygen` to generate Solidity contracts for verification.
