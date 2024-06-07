use crate::{GenericGroupManagerPrivateKey, GenericGroupManagerPublicKey, GenericIccSecretKey, GenericPssSignature, GroupManager, GroupManagerPublicKey, Icc, PssSignature, PssSigner};

use crypto_bigint::{generic_array::{sequence::GenericSequence, GenericArray}, rand_core::OsRng};
use k256::{elliptic_curve::{hash2curve::FromOkm, sec1::ToEncodedPoint, PrimeField, ScalarPrimitive}, AffinePoint, PublicKey, Scalar, SecretKey};
use sha3::{digest::OutputSizeUser, Digest};
use std::ops::{Add, Mul, Sub};

const ID_DSI: &[u8] = b"TODO replace with algorithm id";

fn signature_hash(q: &AffinePoint, a1_i_sector_icc_1: Option<(AffinePoint, &PublicKey)>, a2_i_sector_icc_2: Option<(AffinePoint, &PublicKey)>, pk_sector: &PublicKey, message: &[u8]) -> GenericArray<u8, <sha3::Keccak256 as OutputSizeUser>::OutputSize> {
    let mut c_message_buffer = Vec::new();
    c_message_buffer.extend_from_slice(q.to_encoded_point(true).as_bytes());
    if let Some((a1, i_sector_icc_1)) = a1_i_sector_icc_1 {
        c_message_buffer.extend_from_slice(i_sector_icc_1.to_encoded_point(true).as_bytes());
        c_message_buffer.extend_from_slice(a1.to_encoded_point(true).as_bytes());
    }
    if let Some((a2, i_sector_icc_2)) = a2_i_sector_icc_2 {
        c_message_buffer.extend_from_slice(i_sector_icc_2.to_encoded_point(true).as_bytes());
        c_message_buffer.extend_from_slice(a2.to_encoded_point(true).as_bytes());
    }
    c_message_buffer.extend_from_slice(pk_sector.to_encoded_point(true).as_bytes());
    c_message_buffer.extend_from_slice(ID_DSI);
    c_message_buffer.extend_from_slice(message);


    sha3::Keccak256::digest(&c_message_buffer)
}

fn hash2curve<S: FromOkm>(hash: &[u8]) -> S {
    let array_fitting_length = GenericArray::generate(|idx| {
        if idx < hash.len() {
            hash[idx]
        } else {
            0
        }
    });
    S::from_okm(&array_fitting_length)
}

pub struct SectorSpecificIdentifiers {
    i_sector_icc_1: PublicKey,
    i_sector_icc_2: PublicKey
}

impl SectorSpecificIdentifiers {
    pub fn new(i_sector_icc_1: PublicKey, i_sector_icc_2: PublicKey) -> Self {
        Self { i_sector_icc_1, i_sector_icc_2 }
    }
}

#[derive(Debug, Clone)]
pub struct EccPssSignature {
    c: Scalar,
    s1: Scalar,
    s2: Scalar,
    pseudonyms: (Option<PublicKey>, Option<PublicKey>)
}

impl Into<GenericPssSignature> for EccPssSignature {
    fn into(self) -> GenericPssSignature {
        GenericPssSignature {
            c: self.c.to_bytes().as_slice().into(),
            s1: self.s1.to_bytes().as_slice().into(),
            s2: self.s2.to_bytes().as_slice().into(),
            pseudonym1: self.pseudonyms.0.map(|pk| pk.to_encoded_point(true).to_bytes()),
            pseudonym2: self.pseudonyms.1.map(|pk| pk.to_encoded_point(true).to_bytes())
            
        }
    }
}

impl TryFrom<GenericPssSignature> for EccPssSignature {
    type Error = ();
    fn try_from(value: GenericPssSignature) -> Result<Self, Self::Error> {
        let c = Scalar::from_repr(*GenericArray::from_slice(&value.c)).unwrap();
        let s1 = Scalar::from_repr(*GenericArray::from_slice(&value.s1)).unwrap();
        let s2 = Scalar::from_repr(*GenericArray::from_slice(&value.s2)).unwrap();

        let pseudonyms = (
            value.pseudonym1.map(|spoint| PublicKey::from_sec1_bytes(spoint.as_ref()).unwrap()),
            value.pseudonym2.map(|spoint| PublicKey::from_sec1_bytes(spoint.as_ref()).unwrap())
        );
        Ok(EccPssSignature {
            c, s1, s2, pseudonyms
        })
    }
}

impl PssSignature for EccPssSignature {
    type PublicKey = PublicKey;
    type Scalar = Scalar;

    fn c(&self) -> &Self::Scalar {
        &self.c
    }

    fn s1(&self) -> &Self::Scalar {
        &self.s1
    }

    fn s2(&self) -> &Self::Scalar {
        &self.s2
    }

    fn pseudonym1(&self) -> &Option<Self::PublicKey> {
        &self.pseudonyms.0
    }

    fn pseudonym2(&self) -> &Option<Self::PublicKey> {
        &self.pseudonyms.1
    }
}

#[derive(Debug)]
pub struct EccPssSigner<'a> {
    sk_icc_1_u: &'a SecretKey,
    sk_icc_2_u: &'a SecretKey,
    pk_sector: &'a PublicKey,
    pk_m: &'a PublicKey,
    i_sector_icc_1: Option<PublicKey>,
    i_sector_icc_2: Option<PublicKey>,
}

impl<'a> PssSigner for EccPssSigner<'a> {
    type PssSignature = EccPssSignature;
    
    fn sign(&self, message: &[u8]) -> Self::PssSignature {
        let k1 = SecretKey::random(&mut OsRng::default());
        let k2 = SecretKey::random(&mut OsRng::default());

        let q1_part = self.pk_m.to_projective().mul(Scalar::from(k2.as_scalar_primitive()));
        let q1 = k1.public_key().to_projective().add(&q1_part).to_affine();

        let pk_sector_proj = self.pk_sector.to_projective();

        let pseudonym1 = match self.i_sector_icc_1 {
            Some(ref pubkey) => Some((pk_sector_proj.mul(Scalar::from(k1.as_scalar_primitive())).to_affine(), pubkey)),
            None => None
        };
        let pseudonym2 = match self.i_sector_icc_2 {
            Some(ref pubkey) => Some((pk_sector_proj.mul(Scalar::from(k2.as_scalar_primitive())).to_affine(), pubkey)),
            None => None
        };

        let c_bin = signature_hash(&q1, pseudonym1, pseudonym2, &self.pk_sector, message);
        let c: Scalar = hash2curve(&c_bin);

        let s1 = Scalar::from(k1.as_scalar_primitive()).sub(c.mul(Scalar::from(self.sk_icc_1_u.as_scalar_primitive())));
        let s2 = Scalar::from(k2.as_scalar_primitive()).sub(c.mul(Scalar::from(self.sk_icc_2_u.as_scalar_primitive())));

        EccPssSignature {
            c,
            s1,
            s2,
            pseudonyms: (
                self.i_sector_icc_1,
                self.i_sector_icc_2
            )
        }
    }
}

#[derive(Debug)]
pub struct EccIcc {
    gpk: EccGroupManagerPublicKey,
    sk_icc_1_u: SecretKey,
    sk_icc_2_u: SecretKey
}

impl Icc for EccIcc {
    type GroupManagerPublicKey = EccGroupManagerPublicKey;
    type SecretKey = SecretKey;
    type SectorSpecificIdentifiers = SectorSpecificIdentifiers;
    type PublicKey = PublicKey;
    type Signer<'a> = EccPssSigner<'a>;

    fn new(gpk: Self::GroupManagerPublicKey, sk_icc_1_u: SecretKey, sk_icc_2_u: SecretKey) -> Self {
        let nym = Self { gpk, sk_icc_1_u, sk_icc_2_u };
        assert!(nym.valid_for_gpk(&nym.gpk));
        nym
    }

    fn valid_for_gpk(&self, gpk: &Self::GroupManagerPublicKey) -> bool {
        let pk_icc_1_u = self.sk_icc_1_u.public_key().to_projective();
        let pk_icc_2_u = gpk.pk_m.to_projective().mul(Scalar::from(self.sk_icc_2_u.as_scalar_primitive()));
        let result = pk_icc_1_u + pk_icc_2_u;
        &result.to_affine() == gpk.pk_icc.as_affine()
    }

    fn sector_identifiers(&self, pk_sector: &PublicKey) -> SectorSpecificIdentifiers {
        let i_sector_icc_1 = PublicKey::from_affine(pk_sector.to_projective().mul(Scalar::from(self.sk_icc_1_u.as_scalar_primitive())).to_affine()).unwrap();
        let i_sector_icc_2 = PublicKey::from_affine(pk_sector.to_projective().mul(Scalar::from(self.sk_icc_2_u.as_scalar_primitive())).to_affine()).unwrap();
        SectorSpecificIdentifiers::new(i_sector_icc_1, i_sector_icc_2)
    }

    fn signer<'a>(&'a self, pk_sector: &'a PublicKey, use_identifier1: bool, use_identifier2: bool) -> <Self as Icc>::Signer<'a> {
        let identifiers = self.sector_identifiers(pk_sector);
        let (i_sector_icc_1, i_sector_icc_2) = match (use_identifier1, use_identifier2) {
            (true, true) => (Some(identifiers.i_sector_icc_1), Some(identifiers.i_sector_icc_2)),
            (true, false) => (Some(identifiers.i_sector_icc_1), None),
            (false, true) => (None, Some(identifiers.i_sector_icc_2)),
            (false, false) => (None, None)
        };
        EccPssSigner {
            sk_icc_1_u: &self.sk_icc_1_u,
            sk_icc_2_u: &self.sk_icc_2_u,
            pk_sector: pk_sector,
            pk_m: &self.gpk.pk_m,
            i_sector_icc_1,
            i_sector_icc_2
        }
    }
    
    fn from_generic_secret_key(secret_key: crate::GenericIccSecretKey, gpk: Self::GroupManagerPublicKey) -> Self {
        let sk_icc_1_u = SecretKey::from_slice(&secret_key.sk_icc_1_u).unwrap();
        let sk_icc_2_u = SecretKey::from_slice(&secret_key.sk_icc_2_u).unwrap();
        Self {
            gpk, sk_icc_1_u, sk_icc_2_u
        }
    }
}


impl From<EccIcc> for GenericIccSecretKey {
    fn from(value: EccIcc) -> Self {
        Self { sk_icc_1_u: value.sk_icc_1_u.to_bytes().as_slice().into(), sk_icc_2_u: value.sk_icc_2_u.to_bytes().as_slice().into() }
    }
}

#[derive(Debug)]
pub struct SectorKey(SecretKey);

impl SectorKey {
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }
}

#[derive(Debug)]
pub struct EccGroupManager {
    sk_m: SecretKey,
    sk_icc: SecretKey,
    gpk: EccGroupManagerPublicKey,
    sectors: Vec<(PublicKey, Option<SectorKey>)>
}

impl GroupManager for EccGroupManager {
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;
    type GroupManagerPublicKey = EccGroupManagerPublicKey;
    type Icc = EccIcc;
    
    fn new() -> Self {
        let sk_m = SecretKey::random(&mut OsRng::default());
        let sk_icc = SecretKey::random(&mut OsRng::default());
        Self::new_from_secret_parts(sk_m, sk_icc)
    }

    fn new_from_secret_parts(sk_m: Self::SecretKey, sk_icc: Self::SecretKey) -> Self {
        let pk_m = sk_m.public_key();
        let pk_icc = sk_icc.public_key();
        let gpk = EccGroupManagerPublicKey::new(pk_m, pk_icc);
        let sectors = Vec::new();
        Self { sk_m, sk_icc, gpk, sectors }
    }

    fn renew_icc(&mut self) -> SecretKey {
        let mut sk_icc = SecretKey::random(&mut OsRng::default());
        self.gpk.pk_icc = sk_icc.public_key();
        std::mem::swap(&mut self.sk_icc, &mut sk_icc);
        sk_icc
    }

    fn new_icc(&self) -> EccIcc {
        let sk_icc_2_u = SecretKey::random(&mut OsRng::default());
        let sk_icc_2_u_scalar = Scalar::from(sk_icc_2_u.as_scalar_primitive());
        let sk_m_scalar = Scalar::from(self.sk_m.as_scalar_primitive());
        let sk_icc_scalar = Scalar::from(self.sk_icc.as_scalar_primitive());

        // SK_ICC_1 = SK_ICC - SK_M * SK_ICC_2
        let multiplication = sk_m_scalar.mul(&sk_icc_2_u_scalar);
        let sk_icc_1_u_scalar = sk_icc_scalar.sub(&multiplication);
        let sk_icc_1_u = SecretKey::new(ScalarPrimitive::from(&sk_icc_1_u_scalar));
        EccIcc::new(self.gpk.clone(), sk_icc_1_u, sk_icc_2_u)
    }

    fn new_sector(&mut self, deanonymizable: bool) -> PublicKey {
        let key = SectorKey(SecretKey::random(&mut OsRng::default()));
        let pubkey = key.public_key();
        self.sectors.push((pubkey.clone(), match deanonymizable {
            true => Some(key),
            false => None
        }));
        pubkey
    }

    fn public_key(&self) -> &EccGroupManagerPublicKey {
        &self.gpk
    }
    
    fn from_generic_secret_key(secret_key: crate::GenericGroupManagerPrivateKey, _g: Option<Box<[u8]>>) -> Self {
        Self::new_from_secret_parts(SecretKey::from_slice(&secret_key.sk_m).unwrap(), SecretKey::from_slice(&secret_key.sk_icc).unwrap())
    }
}

impl From<EccGroupManager> for GenericGroupManagerPrivateKey {
    fn from(value: EccGroupManager) -> Self {
        Self {
            sk_m: value.sk_m.to_bytes().as_slice().into(),
            sk_icc: value.sk_icc.to_bytes().as_slice().into()
        }
    }
}

#[derive(Debug, Clone)]
pub struct EccGroupManagerPublicKey {
    pk_m: PublicKey,
    pk_icc: PublicKey
}

impl GroupManagerPublicKey for EccGroupManagerPublicKey {
    type PublicKey = PublicKey;
    type Signature = EccPssSignature;

    fn new(pk_m: Self::PublicKey, pk_icc: Self::PublicKey) -> Self {
        Self { pk_m, pk_icc }
    }

    fn check_signature(&self, message: &[u8], pk_sector: &Self::PublicKey, signature: &Self::Signature) -> bool {
        self.recover_c(message, pk_sector, signature) == signature.c
    }
    
    fn from_generic_gpk(gpk: crate::GenericGroupManagerPublicKey, _g: Option<Box<[u8]>>) -> Self {
        let pk_m = PublicKey::from_sec1_bytes(&gpk.pk_m).unwrap();
        let pk_icc = PublicKey::from_sec1_bytes(&gpk.pk_icc).unwrap();
        Self { pk_icc, pk_m }
    }
}

impl From<EccGroupManagerPublicKey> for GenericGroupManagerPublicKey {
    fn from(value: EccGroupManagerPublicKey) -> Self {
        Self { pk_m: value.pk_m.to_sec1_bytes(), pk_icc: value.pk_icc.to_sec1_bytes() }
    }
}

impl EccGroupManagerPublicKey {
    pub(crate) fn recover_c(&self, message: &[u8], pk_sector: &PublicKey, signature: &EccPssSignature) -> Scalar {
        let q1s1 = self.pk_icc.to_projective().mul(signature.c);
        let q1s2 = SecretKey::new(ScalarPrimitive::from(&signature.s1)).public_key().to_projective();
        let q1s3 = self.pk_m.to_projective().mul(signature.s2);
        let q1 = q1s1.add(&q1s2).add(&q1s3).to_affine();

        let pseudonym1 = match signature.pseudonyms.0 {
            Some(ref pubkey) => {
                let sector_c = pubkey.to_projective().mul(signature.c);
                let pk_s = pk_sector.to_projective().mul(signature.s1);
                let a1 = sector_c.add(&pk_s).to_affine();
                Some((a1, pubkey))
            },
            None => None,
        };
        let pseudonym2 = match signature.pseudonyms.1 {
            Some(ref pubkey) => {
                let sector_c = pubkey.to_projective().mul(signature.c);
                let pk_s = pk_sector.to_projective().mul(signature.s2);
                let a2 = sector_c.add(&pk_s).to_affine();
                Some((a2, pubkey))
            },
            None => None,
        };

        let c_bytes = signature_hash(&q1, pseudonym1, pseudonym2, pk_sector, message);
        let c: Scalar = hash2curve(&c_bytes);

        c
    }
}

#[cfg(test)]
mod tests {
    use k256::Scalar;

    use crate::{ecc::EccPssSignature, GroupManager, GroupManagerPublicKey, Icc, PssSigner};

    use super::EccGroupManager;

    const SIGN_MESSAGE: &[u8] = b"TEST MESSAGE";

    #[test]
    fn valid_keys() {
        let mut group_manager = EccGroupManager::new();
        let nym = group_manager.new_icc();
        assert!(nym.valid_for_gpk(group_manager.public_key()));

        let _ = group_manager.renew_icc();
        assert!(!nym.valid_for_gpk(group_manager.public_key()));
    }

    #[test]
    fn valid_signature() {
        let mut group_manager = EccGroupManager::new();
        let icc = group_manager.new_icc();
        let sector = group_manager.new_sector(false);

        let combinations = vec![(true, true), (true, false), (false, true), (false, false)];
        for (id1, id2) in combinations {
            let signer = icc.signer(&sector, id1, id2);
            let signature = signer.sign(SIGN_MESSAGE);
            assert!(group_manager.public_key().check_signature(SIGN_MESSAGE, &sector, &signature));
        }
    }

    #[test]
    fn invalid_signature() {
        let mut group_manager = EccGroupManager::new();
        let nym = group_manager.new_icc();
        let sector = group_manager.new_sector(false);

        let combinations = vec![(true, true), (true, false), (false, true), (false, false)];
        for (id1, id2) in combinations {
            let signer = nym.signer(&sector, id1, id2);
            let signature = signer.sign(SIGN_MESSAGE);
            fn tamper_with(signature: &mut EccPssSignature, c: bool, s1: bool, s2: bool) {
                if c {
                    signature.c = signature.c.sub(&Scalar::from(1u32));
                }
                if s1 {
                    signature.s1 = signature.s1.sub(&Scalar::from(1u32));
                }
                if s2 {
                    signature.s2 = signature.s2.sub(&Scalar::from(1u32));
                }
            }
            let combinations = vec![(true, true, true), (true, true, false), (true, false, true), (true, false, false), (false, true, true), (false, true, false), (false, false, true)];
            for (c, s1, s2) in combinations {
                let mut signature_to_tamper_with = signature.clone();
                tamper_with(&mut signature_to_tamper_with, c, s1, s2);
                assert!(!group_manager.public_key().check_signature(SIGN_MESSAGE, &sector, &signature_to_tamper_with), "signature was tampered with but still valid! c={} s1={} s2={}", c, s1, s2);
            }
        }
    }
}