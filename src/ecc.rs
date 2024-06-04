use crypto_bigint::{generic_array::{sequence::GenericSequence, GenericArray}, rand_core::OsRng};
use p256::{elliptic_curve::{hash2curve::FromOkm, sec1::ToEncodedPoint, ScalarPrimitive}, AffinePoint, PublicKey, Scalar, SecretKey};
use sha3::{digest::OutputSizeUser, Digest};
use std::ops::{Mul, Sub};

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
pub struct PssSignature {
    c: Scalar,
    s1: Scalar,
    s2: Scalar,
    pseudonyms: (Option<PublicKey>, Option<PublicKey>)
}

#[derive(Debug)]
pub struct PssSigner<'a> {
    sk_icc_1_u: &'a SecretKey,
    sk_icc_2_u: &'a SecretKey,
    pk_sector: &'a PublicKey,
    pk_m: &'a PublicKey,
    i_sector_icc_1: Option<PublicKey>,
    i_sector_icc_2: Option<PublicKey>,
}

impl<'a> PssSigner<'a> {
    pub fn sign(&self, message: &[u8]) -> PssSignature {
        let k1 = SecretKey::random(&mut OsRng::default());
        let k2 = SecretKey::random(&mut OsRng::default());

        let q1_part = self.pk_m.to_projective().mul(Scalar::from(&k2));
        let q1 = k1.public_key().to_projective().add(&q1_part).to_affine();

        let pk_sector_proj = self.pk_sector.to_projective();

        let pseudonym1 = match self.i_sector_icc_1 {
            Some(ref pubkey) => Some((pk_sector_proj.mul(Scalar::from(&k1)).to_affine(), pubkey)),
            None => None
        };
        let pseudonym2 = match self.i_sector_icc_2 {
            Some(ref pubkey) => Some((pk_sector_proj.mul(Scalar::from(&k2)).to_affine(), pubkey)),
            None => None
        };

        let c_bin = signature_hash(&q1, pseudonym1, pseudonym2, &self.pk_sector, message);
        let c: Scalar = hash2curve(&c_bin);

        let s1 = Scalar::from(&k1).sub(c.multiply(&Scalar::from(self.sk_icc_1_u)));
        let s2 = Scalar::from(&k2).sub(c.multiply(&Scalar::from(self.sk_icc_2_u)));

        PssSignature {
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
pub struct NymSecretKey {
    gpk: GroupManagerPublicKey,
    sk_icc_1_u: SecretKey,
    sk_icc_2_u: SecretKey
}

impl NymSecretKey {
    pub fn new(gpk: GroupManagerPublicKey, sk_icc_1_u: SecretKey, sk_icc_2_u: SecretKey) -> Self {
        let nym = Self { gpk, sk_icc_1_u, sk_icc_2_u };
        assert!(nym.valid_for_gpk(&nym.gpk));
        nym
    }

    pub fn valid_for_gpk(&self, gpk: &GroupManagerPublicKey) -> bool {
        let pk_icc_1_u = self.sk_icc_1_u.public_key().to_projective();
        let pk_icc_2_u = gpk.pk_m.to_projective().mul(Scalar::from(&self.sk_icc_2_u));
        let result = pk_icc_1_u + pk_icc_2_u;
        &result.to_affine() == gpk.pk_icc.as_affine()
    }

    pub fn sector_identifiers(&self, pk_sector: &PublicKey) -> SectorSpecificIdentifiers {
        let i_sector_icc_1 = PublicKey::from_affine(pk_sector.to_projective().mul(Scalar::from(&self.sk_icc_1_u)).to_affine()).unwrap();
        let i_sector_icc_2 = PublicKey::from_affine(pk_sector.to_projective().mul(Scalar::from(&self.sk_icc_2_u)).to_affine()).unwrap();
        SectorSpecificIdentifiers::new(i_sector_icc_1, i_sector_icc_2)
    }

    pub fn signer<'pk, 'me: 'pk>(&'me self, pk_sector: &'pk PublicKey, use_identifier1: bool, use_identifier2: bool) -> PssSigner<'pk> {
        let identifiers = self.sector_identifiers(pk_sector);
        let (i_sector_icc_1, i_sector_icc_2) = match (use_identifier1, use_identifier2) {
            (true, true) => (Some(identifiers.i_sector_icc_1), Some(identifiers.i_sector_icc_2)),
            (true, false) => (Some(identifiers.i_sector_icc_1), None),
            (false, true) => (None, Some(identifiers.i_sector_icc_2)),
            (false, false) => (None, None)
        };
        PssSigner {
            sk_icc_1_u: &self.sk_icc_1_u,
            sk_icc_2_u: &self.sk_icc_2_u,
            pk_sector: pk_sector,
            pk_m: &self.gpk.pk_m,
            i_sector_icc_1,
            i_sector_icc_2
        }
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
pub struct GroupManager {
    sk_m: SecretKey,
    sk_icc: SecretKey,
    gpk: GroupManagerPublicKey,
    sectors: Vec<(PublicKey, Option<SectorKey>)>
}

impl GroupManager {
    pub fn new() -> Self {
        let sk_m = SecretKey::random(&mut OsRng::default());
        let sk_icc = SecretKey::random(&mut OsRng::default());
        let pk_m = sk_m.public_key();
        let pk_icc = sk_icc.public_key();
        let gpk = GroupManagerPublicKey::new(pk_m, pk_icc);
        let sectors = Vec::new();
        Self { sk_m, sk_icc, gpk, sectors }
    }

    pub fn renew_icc(&mut self) -> SecretKey {
        let mut sk_icc = SecretKey::random(&mut OsRng::default());
        self.gpk.pk_icc = sk_icc.public_key();
        std::mem::swap(&mut self.sk_icc, &mut sk_icc);
        sk_icc
    }

    pub fn nym(&self) -> NymSecretKey {
        let sk_icc_2_u = SecretKey::random(&mut OsRng::default());
        let sk_icc_2_u_scalar = Scalar::from(&sk_icc_2_u);
        let sk_m_scalar = Scalar::from(&self.sk_m);
        let sk_icc_scalar = Scalar::from(&self.sk_icc);

        // SK_ICC_1 = SK_ICC - SK_M * SK_ICC_2
        let multiplication = sk_m_scalar.multiply(&sk_icc_2_u_scalar);
        let sk_icc_1_u_scalar = sk_icc_scalar.sub(&multiplication);
        let sk_icc_1_u = SecretKey::new(ScalarPrimitive::from(&sk_icc_1_u_scalar));
        NymSecretKey::new(self.gpk.clone(), sk_icc_1_u, sk_icc_2_u)
    }

    pub fn sector(&mut self, deanonymizable: bool) -> PublicKey {
        let key = SectorKey(SecretKey::random(&mut OsRng::default()));
        let pubkey = key.public_key();
        self.sectors.push((pubkey.clone(), match deanonymizable {
            true => Some(key),
            false => None
        }));
        pubkey
    }

    pub fn public_key(&self) -> &GroupManagerPublicKey {
        &self.gpk
    }
}

#[derive(Debug, Clone)]
pub struct GroupManagerPublicKey {
    pk_m: PublicKey,
    pk_icc: PublicKey
}

impl GroupManagerPublicKey {
    pub fn new(pk_m: PublicKey, pk_icc: PublicKey) -> Self {
        Self { pk_m, pk_icc }
    }

    pub fn check_signature(&self, message: &[u8], pk_sector: &PublicKey, signature: &PssSignature) -> bool {
        self.recover_c(message, pk_sector, signature) == signature.c
    }

    pub(crate) fn recover_c(&self, message: &[u8], pk_sector: &PublicKey, signature: &PssSignature) -> Scalar {
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
    use p256::Scalar;

    use crate::ecc::PssSignature;

    use super::GroupManager;

    const SIGN_MESSAGE: &[u8] = b"TEST MESSAGE";

    #[test]
    fn valid_keys() {
        let mut group_manager = GroupManager::new();
        let nym = group_manager.nym();
        assert!(nym.valid_for_gpk(group_manager.public_key()));

        let _ = group_manager.renew_icc();
        assert!(!nym.valid_for_gpk(group_manager.public_key()));
    }

    #[test]
    fn valid_signature() {
        let mut group_manager = GroupManager::new();
        let nym = group_manager.nym();
        let sector = group_manager.sector(false);

        let combinations = vec![(true, true), (true, false), (false, true), (false, false)];
        for (id1, id2) in combinations {
            let signer = nym.signer(&sector, id1, id2);
            let signature = signer.sign(SIGN_MESSAGE);
            assert!(group_manager.public_key().check_signature(SIGN_MESSAGE, &sector, &signature));
        }
    }

    #[test]
    fn invalid_signature() {
        let mut group_manager = GroupManager::new();
        let nym = group_manager.nym();
        let sector = group_manager.sector(false);

        let combinations = vec![(true, true), (true, false), (false, true), (false, false)];
        for (id1, id2) in combinations {
            let signer = nym.signer(&sector, id1, id2);
            let signature = signer.sign(SIGN_MESSAGE);
            fn tamper_with(signature: &mut PssSignature, c: bool, s1: bool, s2: bool) {
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