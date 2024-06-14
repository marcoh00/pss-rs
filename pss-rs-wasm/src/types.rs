use js_sys::{wasm_bindgen, Uint8Array};
use pss_rs::{GenericGroupManagerPrivateKey, GenericGroupManagerPublicKey, GenericIccSecretKey, GenericPssSignature, GenericPublicKey, GroupManager, GroupManagerPublicKey, Icc, PssSignature};

use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
#[derive(Clone)]
pub struct JsPssSignature {
    pub c: Uint8Array,
    pub s1: Uint8Array,
    pub s2: Uint8Array,
    pub pseudonym1: Option<Uint8Array>,
    pub pseudonym2: Option<Uint8Array>
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
            sk_icc: self.sk_icc.to_vec().into_boxed_slice()
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
    pub pk_icc: Uint8Array
}

impl From<GenericGroupManagerPublicKey> for JsGroupManagerPublicKey {
    fn from(value: GenericGroupManagerPublicKey) -> Self {
        Self {
            pk_m: value.pk_m.as_ref().into(),
            pk_icc: value.pk_icc.as_ref().into()
        }
    }
}

impl Into<GenericGroupManagerPublicKey> for JsGroupManagerPublicKey {
    fn into(self) -> GenericGroupManagerPublicKey {
        GenericGroupManagerPublicKey {
            pk_m: self.pk_m.to_vec().into_boxed_slice(),
            pk_icc: self.pk_icc.to_vec().into_boxed_slice()
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
    pub sk_icc_2_u: Uint8Array
}

impl From<GenericIccSecretKey> for JsIccSecretKey {
    fn from(value: GenericIccSecretKey) -> Self {
        Self {
            sk_icc_1_u: value.sk_icc_1_u.as_ref().into(),
            sk_icc_2_u: value.sk_icc_2_u.as_ref().into()
        }
    }
}

impl Into<GenericIccSecretKey> for JsIccSecretKey {
    fn into(self) -> GenericIccSecretKey {
        GenericIccSecretKey {
            sk_icc_1_u: self.sk_icc_1_u.to_vec().into_boxed_slice(),
            sk_icc_2_u: self.sk_icc_2_u.to_vec().into_boxed_slice()
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
pub struct JsPublicKey(pub Uint8Array);

impl From<GenericPublicKey> for JsPublicKey {
    fn from(value: GenericPublicKey) -> Self {
        Self(value.0.as_ref().into())
    }
}

impl Into<GenericPublicKey> for JsPublicKey {
    fn into(self) -> GenericPublicKey {
        GenericPublicKey(self.0.to_vec().into_boxed_slice())
    }
}

impl JsPublicKey {
    pub fn from_public_key<T: Into<GenericPublicKey>>(pk: T) -> Self {
        JsPublicKey::from(pk.into())
    }
}
