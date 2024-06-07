mod group;
mod ecc;

pub trait GroupManager {
    type SecretKey;
    type PublicKey;
    type GroupManagerPublicKey: GroupManagerPublicKey;
    type Icc: Icc;

    fn new() -> Self where Self: Sized;
    fn renew_icc(&mut self) -> Self::SecretKey;
    fn new_icc(&self) -> Self::Icc;
    fn new_sector(&mut self, deanonymizable: bool) -> Self::PublicKey;
    fn public_key(&self) -> &Self::GroupManagerPublicKey;
}

pub trait Icc {
    type GroupManagerPublicKey: GroupManagerPublicKey;
    type SecretKey;
    type SectorSpecificIdentifiers;
    type PublicKey;
    type Signer<'a>: PssSigner where Self: 'a;

    fn new(gpk: Self::GroupManagerPublicKey, sk_icc_1_u: Self::SecretKey, sk_icc_2_u: Self::SecretKey) -> Self;
    fn valid_for_gpk(&self, gpk: &Self::GroupManagerPublicKey) -> bool;
    fn sector_identifiers(&self, pk_sector: &Self::PublicKey) -> Self::SectorSpecificIdentifiers;
    fn signer<'a>(&'a self, pk_sector: &'a Self::PublicKey, use_identifier1: bool, use_identifier2: bool) -> Self::Signer<'a>;
}

pub trait PssSigner {
    type PssSignature: PssSignature;

    fn sign(&self, message: &[u8]) -> Self::PssSignature;
}

pub trait GroupManagerPublicKey {
    type PublicKey;
    type Signature: PssSignature;

    fn new(pk_m: Self::PublicKey, pk_icc: Self::PublicKey) -> Self where Self: Sized;
    fn check_signature(&self, message: &[u8], pk_sector: &Self::PublicKey, signature: &Self::Signature) -> bool;
}

pub trait PssSignature: Into<GenericPssSignature> + TryFrom<GenericPssSignature> {
    type PublicKey;
    type Scalar;

    fn c(&self) -> &Self::Scalar;
    fn s1(&self) -> &Self::Scalar;
    fn s2(&self) -> &Self::Scalar;
    fn pseudonym1(&self) -> &Option<Self::PublicKey>;
    fn pseudonym2(&self) -> &Option<Self::PublicKey>;
}

pub struct GenericPssSignature {
    c: Box<[u8]>,
    s1: Box<[u8]>,
    s2: Box<[u8]>,
    pseudonyms: (Option<Box<[u8]>>, Option<Box<[u8]>>)
}
