use k256::Secp256k1;
use pss_rs::{rustcryptoecc::{EccGroupManager, EccIcc}, GroupManager, Icc, PssSigner};

#[allow(long_running_const_eval)]
use wasm_bindgen::prelude::*;

mod types;
use types::*;

#[cfg(feature = "dh")]
mod dh {
    pub use pss_rs::group::{GroupGroupManager, DH_MODP_2048};
}

#[wasm_bindgen]
pub enum Algorithm {
    Secp256k1,
    DH2048
}

#[wasm_bindgen(getter_with_clone)]
pub struct TSystem {
    pub gpub: JsGroupManagerPublicKey,
    pub gprv: JsGroupManagerPrivateKey,
    pub iccprv: JsIccSecretKey,
    pub sig: JsPssSignature,
    pub sector: JsPublicKey
}

// TODO need generic sector key
#[wasm_bindgen]
pub fn sig_new_ident(alg: Algorithm, msg: &[u8]) -> TSystem {
    match alg {
        #[cfg(feature = "dh")]
        Algorithm::DH2048 => {
            let mut gm = dh::GroupGroupManager::new(Some(dh::DH_MODP_2048));
            let icc = gm.new_icc();
            let sector = gm.new_sector(false);
            let signer = icc.signer(&sector, true, true);
            let signature = signer.sign(msg);
            TSystem {
                gpub: JsGroupManagerPublicKey::from_group_manager_public_key(gm.public_key().clone()),
                gprv: JsGroupManagerPrivateKey::from_group_manager(gm),
                iccprv: JsIccSecretKey::from_icc(icc),
                sig: JsPssSignature::from_pss_signature(signature),
                sector: JsPublicKey::from_public_key(sector)
            }
        },
        #[cfg(not(feature = "dh"))]
        Algorithm::DH2048 => { panic!("Library compiled without support for DH") },
        Algorithm::Secp256k1 => {
            let mut gm = EccGroupManager::new(None);
            let icc: EccIcc<Secp256k1> = gm.new_icc();
            let sector = gm.new_sector(false);
            let signer = icc.signer(&sector, true, true);
            let signature = signer.sign(msg);
            TSystem {
                gpub: JsGroupManagerPublicKey::from_group_manager_public_key(gm.public_key().clone()),
                gprv: JsGroupManagerPrivateKey::from_group_manager(gm),
                iccprv: JsIccSecretKey::from_icc(icc),
                sig: JsPssSignature::from_pss_signature(signature),
                sector: JsPublicKey::from_public_key(sector)
            }
        },
    }
}

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}
