use crypto_bigint::{ConcatMixed, NonZero, Uint};

pub mod ecc;
pub mod rustcryptoecc;
#[cfg(feature = "dh")]
pub mod dh;

fn mul_mod<const LIMBS: usize, const WIDE_LIMBS: usize>(a: &Uint<LIMBS>, b: &Uint<LIMBS>, p: &Uint<LIMBS>) -> Uint<LIMBS>
where Uint<LIMBS>: ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>> {
    let mul = a.mul(&b);
    let wide_modulus = Uint::<LIMBS>::from_u8(0).concat_mixed(p);
    let residue = mul.rem(&NonZero::from_uint(wide_modulus));
    residue.resize()
}

pub trait GroupManager: Into<GenericGroupManagerPrivateKey> {
    type SecretKey;
    type PublicKey: TryFrom<Box<[u8]>> + Into<Box<[u8]>>;
    type GroupManagerPublicKey: GroupManagerPublicKey<PublicKey = Self::PublicKey>;
    type Icc: Icc<SecretKey = Self::SecretKey, PublicKey = Self::PublicKey>;
    type Base;

    fn new(g: Option<Self::Base>) -> Self where Self: Sized;
    fn new_from_secret_parts(sk_m: Self::SecretKey, sk_icc: Self::SecretKey, g: Option<Self::Base>) -> Self;
    fn renew_icc(&mut self) -> Self::SecretKey;
    fn new_icc(&self) -> Self::Icc;
    fn new_sector(&mut self, deanonymizable: bool) -> Self::PublicKey;
    fn public_key(&self) -> &Self::GroupManagerPublicKey;

    fn from_generic_secret_key(secret_key: GenericGroupManagerPrivateKey, g: Option<Box<[u8]>>) -> Self;
}

pub trait Icc: Into<GenericIccSecretKey> {
    type GroupManagerPublicKey: GroupManagerPublicKey<PublicKey = Self::PublicKey>;
    type SecretKey;
    type SectorSpecificIdentifiers;
    type PublicKey: TryFrom<Box<[u8]>> + Into<Box<[u8]>>;
    type Signer<'a>: PssSigner where Self: 'a;

    fn new(gpk: Self::GroupManagerPublicKey, sk_icc_1_u: Self::SecretKey, sk_icc_2_u: Self::SecretKey) -> Self;
    fn valid_for_gpk(&self, gpk: &Self::GroupManagerPublicKey) -> bool;
    fn sector_identifiers(&self, pk_sector: &Self::PublicKey) -> Self::SectorSpecificIdentifiers;
    fn signer<'a>(&'a self, pk_sector: &'a Self::PublicKey, use_identifier1: bool, use_identifier2: bool) -> Self::Signer<'a>;

    fn from_generic_secret_key(secret_key: GenericIccSecretKey, gpk: Self::GroupManagerPublicKey) -> Self;
}

pub trait PssSigner {
    type PssSignature: PssSignature;

    fn sign(&self, message: &[u8]) -> Self::PssSignature;
}

pub trait GroupManagerPublicKey: Into<GenericGroupManagerPublicKey> {
    type PublicKey: TryFrom<Box<[u8]>> + Into<Box<[u8]>>;
    type Signature: PssSignature;
    type Base;

    fn new(pk_m: Self::PublicKey, pk_icc: Self::PublicKey, _g: Option<Self::Base>) -> Self where Self: Sized;
    fn check_signature(&self, message: &[u8], pk_sector: &Self::PublicKey, signature: &Self::Signature) -> bool;

    fn from_generic_gpk(gpk: GenericGroupManagerPublicKey, g: Option<Box<[u8]>>) -> Self;
}

pub trait PssSignature: Into<GenericPssSignature> + TryFrom<GenericPssSignature> {
    type PublicKey: TryFrom<Box<[u8]>> + Into<Box<[u8]>>;
    type Scalar;

    fn c(&self) -> &Self::Scalar;
    fn s1(&self) -> &Self::Scalar;
    fn s2(&self) -> &Self::Scalar;
    fn pseudonym1(&self) -> &Option<Self::PublicKey>;
    fn pseudonym2(&self) -> &Option<Self::PublicKey>;
}

#[derive(Debug)]
pub struct GenericPssSignature {
    pub c: Box<[u8]>,
    pub s1: Box<[u8]>,
    pub s2: Box<[u8]>,
    pub pseudonym1: Option<Box<[u8]>>,
    pub pseudonym2: Option<Box<[u8]>>
}

#[derive(Debug)]
pub struct GenericGroupManagerPrivateKey {
    pub sk_m: Box<[u8]>,
    pub sk_icc: Box<[u8]>,
}

#[derive(Debug)]
pub struct GenericGroupManagerPublicKey {
    pub pk_m: Box<[u8]>,
    pub pk_icc: Box<[u8]>
}

#[derive(Debug)]
pub struct GenericIccSecretKey {
    pub sk_icc_1_u: Box<[u8]>,
    pub sk_icc_2_u: Box<[u8]>
}

#[derive(Debug)]
pub struct GenericPublicKey(pub Box<[u8]>);

impl From<Box<[u8]>> for GenericPublicKey {
    fn from(value: Box<[u8]>) -> Self {
        Self(value)
    }
}

impl Into<Box<[u8]>> for GenericPublicKey {
    fn into(self) -> Box<[u8]> {
        self.0
    }
}

impl AsRef<[u8]> for GenericPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
