use js_sys::{wasm_bindgen, Uint8Array};
use pss_rs::{
    ecc::{EccGroupManager, EccGroupManagerPublicKey, EccIcc, EccPssSignature},
    rustcryptoecc::PssSecp256k1,
    GenericGroupManagerPrivateKey, GenericGroupManagerPublicKey, GenericIccSecretKey,
    GenericPssSignature, GroupManager, GroupManagerPublicKey, Icc, PssSignature, PssSigner,
};

use crate::Algorithm;
use pss_rs::ecc::PssCompatibleEccCurve;
use wasm_bindgen::prelude::*;

#[cfg(feature = "altbn")]
use pss_rs::altbn::PssAltBn128;

#[cfg(feature = "dh")]
mod dh {
    use pss_rs::dh::{ConcatMixed, ResidueParams, Uint};
    pub use pss_rs::dh::{
        DhModp2048Modulus, GroupGroupManager, GroupGroupManagerPublicKey, GroupIcc,
        GroupPssSignature, DH_MODP_2048,
    };
    pub const DH2048_LIMBS: usize = DhModp2048Modulus::LIMBS;
    pub const DH2048_WIDE_LIMBS: usize = <Uint<DH2048_LIMBS> as ConcatMixed>::MixedOutput::LIMBS;
    pub type Dh2048GroupManager =
        GroupGroupManager<DH2048_LIMBS, DH2048_WIDE_LIMBS, DhModp2048Modulus>;
}

type Secp256k1GroupManager = EccGroupManager<PssSecp256k1>;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Clone)]
pub struct JsPssSignature {
    pub c: Uint8Array,
    pub s1: Uint8Array,
    pub s2: Uint8Array,
    pub pseudonym1: Option<Uint8Array>,
    pub pseudonym2: Option<Uint8Array>,
}

impl From<GenericPssSignature> for JsPssSignature {
    fn from(value: GenericPssSignature) -> Self {
        Self {
            c: Uint8Array::from(value.c.as_ref()).into(),
            s1: value.s1.as_ref().into(),
            s2: value.s2.as_ref().into(),
            pseudonym1: value.pseudonym1.map(|v| v.as_ref().into()),
            pseudonym2: value.pseudonym2.map(|v| v.as_ref().into()),
        }
    }
}

impl Into<GenericPssSignature> for JsPssSignature {
    fn into(self) -> GenericPssSignature {
        GenericPssSignature {
            c: self.c.to_vec().into_boxed_slice(),
            s1: self.s1.to_vec().into_boxed_slice(),
            s2: self.s2.to_vec().into_boxed_slice(),
            pseudonym1: self.pseudonym1.map(|v| v.to_vec().into_boxed_slice()),
            pseudonym2: self.pseudonym2.map(|v| v.to_vec().into_boxed_slice()),
        }
    }
}

impl JsPssSignature {
    pub fn from_pss_signature<T: PssSignature>(sig: T) -> Self {
        Self::from(sig.into())
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Clone)]
pub struct JsGroupManagerPrivateKey {
    pub sk_m: Uint8Array,
    pub sk_icc: Uint8Array,
}

#[wasm_bindgen]
impl JsGroupManagerPrivateKey {
    #[wasm_bindgen(constructor)]
    pub fn new(sk_m: Uint8Array, sk_icc: Uint8Array) -> Self {
        Self { sk_m, sk_icc }
    }

    pub fn generate(algorithm: Algorithm) -> Self {
        match algorithm {
            #[cfg(feature = "dh")]
            Algorithm::DH2048 => JsGroupManagerPrivateKey::from_group_manager(
                dh::GroupGroupManager::new(Some(dh::DH_MODP_2048)),
            ),
            #[cfg(not(feature = "dh"))]
            Algorithm::DH2048 => {
                panic!("Library compiled without support for DH")
            }
            #[cfg(feature = "altbn")]
            Algorithm::AltBn128 => {
                JsGroupManagerPrivateKey::from_group_manager(EccGroupManager::<PssAltBn128>::new(
                    None,
                ))
            }
            #[cfg(not(feature = "altbn"))]
            Algorithm::AltBn128 => {
                panic!("Library compiled without support for alt_bn128")
            }
            Algorithm::Secp256k1 => {
                JsGroupManagerPrivateKey::from_group_manager(Secp256k1GroupManager::new(None))
            }
        }
    }

    pub fn new_icc(&self, algorithm: Algorithm) -> JsIccSecretKey {
        match algorithm {
            #[cfg(feature = "dh")]
            Algorithm::DH2048 => {
                let generic = self.clone().into();
                let gm = dh::Dh2048GroupManager::from_generic_secret_key(
                    generic,
                    Some(dh::DH_MODP_2048.into()),
                );
                JsIccSecretKey::from_icc(gm.new_icc())
            }
            #[cfg(not(feature = "dh"))]
            Algorithm::DH2048 => {
                panic!("Library compiled without support for DH")
            }
            #[cfg(feature = "altbn")]
            Algorithm::AltBn128 => self.new_icc_ecc::<PssAltBn128>(),
            #[cfg(not(feature = "altbn"))]
            Algorithm::AltBn128 => {
                panic!("Library compiled without support for alt_bn128")
            }
            Algorithm::Secp256k1 => self.new_icc_ecc::<PssSecp256k1>(),
        }
    }

    pub fn new_sector(&self, algorithm: Algorithm, deanonymizable: bool) -> JsPublicKey {
        match algorithm {
            #[cfg(feature = "dh")]
            Algorithm::DH2048 => {
                let generic = self.clone().into();
                let mut gm = dh::Dh2048GroupManager::from_generic_secret_key(
                    generic,
                    Some(dh::DH_MODP_2048.into()),
                );
                JsPublicKey::from_public_key(gm.new_sector(deanonymizable))
            }
            #[cfg(not(feature = "dh"))]
            Algorithm::DH2048 => {
                panic!("Library compiled without support for DH")
            }
            #[cfg(feature = "altbn")]
            Algorithm::AltBn128 => self.new_sector_ecc::<PssAltBn128>(deanonymizable),
            #[cfg(not(feature = "altbn"))]
            Algorithm::AltBn128 => {
                panic!("Library compiled without support for alt_bn128")
            }
            Algorithm::Secp256k1 => self.new_sector_ecc::<PssSecp256k1>(deanonymizable),
        }
    }

    pub fn public_key(&self, algorithm: Algorithm) -> JsGroupManagerPublicKey {
        match algorithm {
            #[cfg(feature = "dh")]
            Algorithm::DH2048 => {
                let generic = self.clone().into();
                let gm = dh::Dh2048GroupManager::from_generic_secret_key(
                    generic,
                    Some(dh::DH_MODP_2048.into()),
                );
                JsGroupManagerPublicKey::from_group_manager_public_key(gm.public_key().clone())
            }
            #[cfg(not(feature = "dh"))]
            Algorithm::DH2048 => {
                panic!("Library compiled without support for DH")
            }
            #[cfg(feature = "altbn")]
            Algorithm::AltBn128 => self.public_key_ecc::<PssAltBn128>(),
            #[cfg(not(feature = "altbn"))]
            Algorithm::AltBn128 => {
                panic!("Library compiled without support for alt_bn128")
            }
            Algorithm::Secp256k1 => self.public_key_ecc::<PssSecp256k1>(),
        }
    }
}

impl JsGroupManagerPrivateKey {
    fn new_icc_ecc<C: PssCompatibleEccCurve>(&self) -> JsIccSecretKey {
        let generic = self.clone().into();
        let gm = EccGroupManager::<C>::from_generic_secret_key(generic, None);
        JsIccSecretKey::from_icc(gm.new_icc())
    }

    fn new_sector_ecc<C: PssCompatibleEccCurve>(&self, deanonymizable: bool) -> JsPublicKey {
        let generic = self.clone().into();
        let mut gm = EccGroupManager::<C>::from_generic_secret_key(generic, None);
        JsPublicKey::from_public_key(gm.new_sector(deanonymizable))
    }

    fn public_key_ecc<C: PssCompatibleEccCurve>(&self) -> JsGroupManagerPublicKey {
        let generic = self.clone().into();
        let gm = EccGroupManager::<C>::from_generic_secret_key(generic, None);
        JsGroupManagerPublicKey::from_group_manager_public_key(gm.public_key().clone())
    }
}

impl From<GenericGroupManagerPrivateKey> for JsGroupManagerPrivateKey {
    fn from(value: GenericGroupManagerPrivateKey) -> Self {
        Self {
            sk_m: value.sk_m.as_ref().into(),
            sk_icc: value.sk_icc.as_ref().into(),
        }
    }
}

impl Into<GenericGroupManagerPrivateKey> for JsGroupManagerPrivateKey {
    fn into(self) -> GenericGroupManagerPrivateKey {
        GenericGroupManagerPrivateKey {
            sk_m: self.sk_m.to_vec().into_boxed_slice(),
            sk_icc: self.sk_icc.to_vec().into_boxed_slice(),
        }
    }
}

impl JsGroupManagerPrivateKey {
    pub fn from_group_manager<T: GroupManager>(gm: T) -> Self {
        JsGroupManagerPrivateKey::from(gm.into())
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Clone)]
pub struct JsGroupManagerPublicKey {
    pub pk_m: Uint8Array,
    pub pk_icc: Uint8Array,
}

#[wasm_bindgen]
impl JsGroupManagerPublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(pk_m: Uint8Array, pk_icc: Uint8Array) -> Self {
        Self { pk_m, pk_icc }
    }

    pub fn check_signature(
        &self,
        algorithm: Algorithm,
        sector: &JsPublicKey,
        signature: &JsPssSignature,
        message: &Uint8Array,
    ) -> bool {
        match algorithm {
            #[cfg(feature = "dh")]
            Algorithm::DH2048 => {
                let gpk = dh::GroupGroupManagerPublicKey::from_generic_gpk(
                    self.clone().into(),
                    Some(dh::DH_MODP_2048.into()),
                );
                let sector = <dh::GroupIcc<
                    { dh::DH2048_LIMBS },
                    { dh::DH2048_WIDE_LIMBS },
                    dh::DhModp2048Modulus,
                > as Icc>::PublicKey::try_from(
                    <JsPublicKey as Into<Box<[u8]>>>::into(sector.clone()),
                )
                .unwrap();
                let signature =
                    dh::GroupPssSignature::try_from(<JsPssSignature as Into<
                        GenericPssSignature,
                    >>::into(signature.clone()))
                    .unwrap();
                gpk.check_signature(&message.to_vec(), &sector, &signature)
            }
            #[cfg(not(feature = "dh"))]
            Algorithm::DH2048 => {
                panic!("Library compiled without support for DH")
            }
            #[cfg(feature = "altbn")]
            Algorithm::AltBn128 => {
                self.check_signature_ecc::<PssAltBn128>(sector, signature, message)
            }
            #[cfg(not(feature = "altbn"))]
            Algorithm::AltBn128 => {
                panic!("Library compiled without support for alt_bn128")
            }
            Algorithm::Secp256k1 => {
                self.check_signature_ecc::<PssSecp256k1>(sector, signature, message)
            }
        }
    }
}

impl JsGroupManagerPublicKey {
    pub fn check_signature_ecc<C: PssCompatibleEccCurve>(
        &self,
        sector: &JsPublicKey,
        signature: &JsPssSignature,
        message: &Uint8Array,
    ) -> bool {
        let gpk = EccGroupManagerPublicKey::from_generic_gpk(self.clone().into(), None);
        let sector = <EccIcc<C> as Icc>::PublicKey::try_from(
            <JsPublicKey as Into<Box<[u8]>>>::into(sector.clone()),
        )
        .unwrap();
        let signature = EccPssSignature::<C>::try_from(<JsPssSignature as Into<
            GenericPssSignature,
        >>::into(signature.clone()))
        .unwrap();
        gpk.check_signature(&message.to_vec(), &sector, &signature)
    }
}

impl From<GenericGroupManagerPublicKey> for JsGroupManagerPublicKey {
    fn from(value: GenericGroupManagerPublicKey) -> Self {
        Self {
            pk_m: value.pk_m.as_ref().into(),
            pk_icc: value.pk_icc.as_ref().into(),
        }
    }
}

impl Into<GenericGroupManagerPublicKey> for JsGroupManagerPublicKey {
    fn into(self) -> GenericGroupManagerPublicKey {
        GenericGroupManagerPublicKey {
            pk_m: self.pk_m.to_vec().into_boxed_slice(),
            pk_icc: self.pk_icc.to_vec().into_boxed_slice(),
        }
    }
}

impl JsGroupManagerPublicKey {
    pub fn from_group_manager_public_key<T: GroupManagerPublicKey>(gmpk: T) -> Self {
        JsGroupManagerPublicKey::from(gmpk.into())
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Clone)]
pub struct JsIccSecretKey {
    pub sk_icc_1_u: Uint8Array,
    pub sk_icc_2_u: Uint8Array,
}

#[wasm_bindgen]
impl JsIccSecretKey {
    #[wasm_bindgen(constructor)]
    pub fn new(sk_icc_1_u: Uint8Array, sk_icc_2_u: Uint8Array) -> Self {
        Self {
            sk_icc_1_u,
            sk_icc_2_u,
        }
    }

    pub fn sign(
        &self,
        algorithm: Algorithm,
        gpk: &JsGroupManagerPublicKey,
        sector: &JsPublicKey,
        use_identifier1: bool,
        use_identifier2: bool,
        message: &Uint8Array,
    ) -> JsPssSignature {
        match algorithm {
            #[cfg(feature = "dh")]
            Algorithm::DH2048 => {
                let gpk = dh::GroupGroupManagerPublicKey::from_generic_gpk(
                    gpk.clone().into(),
                    Some(dh::DH_MODP_2048.into()),
                );
                let sector = <dh::GroupIcc<
                    { dh::DH2048_LIMBS },
                    { dh::DH2048_WIDE_LIMBS },
                    dh::DhModp2048Modulus,
                > as Icc>::PublicKey::try_from(
                    <JsPublicKey as Into<Box<[u8]>>>::into(sector.clone()),
                )
                .unwrap();
                let icc = dh::GroupIcc::from_generic_secret_key(self.clone().into(), gpk);
                let signer = icc.signer(&sector, use_identifier1, use_identifier2);
                let sig = signer.sign(&message.to_vec());
                JsPssSignature::from_pss_signature(sig)
            }
            #[cfg(not(feature = "dh"))]
            Algorithm::DH2048 => {
                panic!("Library compiled without support for DH")
            }
            #[cfg(feature = "altbn")]
            Algorithm::AltBn128 => {
                self.sign_ecc::<PssAltBn128>(gpk, sector, use_identifier1, use_identifier2, message)
            }
            #[cfg(not(feature = "altbn"))]
            Algorithm::AltBn128 => {
                panic!("Library compiled without support for alt_bn128")
            }
            Algorithm::Secp256k1 => self.sign_ecc::<PssSecp256k1>(
                gpk,
                sector,
                use_identifier1,
                use_identifier2,
                message,
            ),
        }
    }
}

impl JsIccSecretKey {
    fn sign_ecc<C: PssCompatibleEccCurve>(
        &self,
        gpk: &JsGroupManagerPublicKey,
        sector: &crate::types::JsPublicKey,
        use_identifier1: bool,
        use_identifier2: bool,
        message: &Uint8Array,
    ) -> JsPssSignature {
        let gpk = EccGroupManagerPublicKey::<C>::from_generic_gpk(gpk.clone().into(), None);
        let sector = <EccIcc<C> as Icc>::PublicKey::try_from(
            <JsPublicKey as Into<Box<[u8]>>>::into(sector.clone()),
        )
        .unwrap();
        let icc = EccIcc::from_generic_secret_key(self.clone().into(), gpk);
        let signer = icc.signer(&sector, use_identifier1, use_identifier2);
        let sig = signer.sign(&message.to_vec());
        JsPssSignature::from_pss_signature(sig)
    }
}

impl From<GenericIccSecretKey> for JsIccSecretKey {
    fn from(value: GenericIccSecretKey) -> Self {
        Self {
            sk_icc_1_u: value.sk_icc_1_u.as_ref().into(),
            sk_icc_2_u: value.sk_icc_2_u.as_ref().into(),
        }
    }
}

impl Into<GenericIccSecretKey> for JsIccSecretKey {
    fn into(self) -> GenericIccSecretKey {
        GenericIccSecretKey {
            sk_icc_1_u: self.sk_icc_1_u.to_vec().into_boxed_slice(),
            sk_icc_2_u: self.sk_icc_2_u.to_vec().into_boxed_slice(),
        }
    }
}

impl JsIccSecretKey {
    pub fn from_icc<T: Icc>(icc: T) -> Self {
        JsIccSecretKey::from(icc.into())
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Clone)]
pub struct JsPublicKey {
    pub pk: Uint8Array,
}

#[wasm_bindgen]
impl JsPublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(pk: Uint8Array) -> Self {
        Self { pk }
    }
}

impl From<Box<[u8]>> for JsPublicKey {
    fn from(value: Box<[u8]>) -> Self {
        Self {
            pk: value.as_ref().into(),
        }
    }
}

impl Into<Box<[u8]>> for JsPublicKey {
    fn into(self) -> Box<[u8]> {
        self.pk.to_vec().into_boxed_slice()
    }
}

impl JsPublicKey {
    pub fn from_public_key<T: Into<Box<[u8]>>>(pk: T) -> Self {
        JsPublicKey::from(pk.into())
    }
}
