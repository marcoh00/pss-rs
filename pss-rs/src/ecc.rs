use crate::{
    GenericGroupManagerPrivateKey, GenericGroupManagerPublicKey, GenericIccSecretKey,
    GenericPssSignature, GroupManager, GroupManagerPublicKey, Icc, PssSignature, PssSigner,
};

use crypto_bigint::{generic_array::GenericArray, rand_core::OsRng};


use rand_core::CryptoRngCore;
use sha3::Digest;
use std::marker::PhantomData;

const ID_DSI: &[u8] = b"ECC-KECCAK256";
pub trait Scalar<C> {
    type Point: Point<C>;

    fn random(rng: &mut impl CryptoRngCore) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn to_point(&self) -> Self::Point;
    fn from_hash(hash: &[u8]) -> Self;
}

pub trait Point<C> {
    type Scalar: Scalar<C>;

    fn base() -> Self;
    fn random(rng: &mut impl CryptoRngCore) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self::Scalar) -> Self;
}

pub trait PssCompatibleEccCurve: Clone {
    type Curve;
    type Scalar: Scalar<Self::Curve, Point = Self::Point>
        + Clone
        + TryFrom<Box<[u8]>>
        + Into<Box<[u8]>>
        + PartialEq;
    type Point: Point<Self::Curve, Scalar = Self::Scalar>
        + Clone
        + TryFrom<Box<[u8]>>
        + Into<Box<[u8]>>
        + PartialEq;
}

fn signature_hash<C: PssCompatibleEccCurve, D: Digest>(
    q: &C::Point,
    a1_i_sector_icc_1: Option<(C::Point, &C::Point)>,
    a2_i_sector_icc_2: Option<(C::Point, &C::Point)>,
    pk_sector: &C::Point,
    message: &[u8],
) -> GenericArray<u8, D::OutputSize> {
    let mut c_message_buffer = Vec::new();
    c_message_buffer.extend_from_slice(&Into::<Box<[u8]>>::into(q.clone()));
    if let Some((a1, i_sector_icc_1)) = a1_i_sector_icc_1 {
        c_message_buffer.extend_from_slice(&Into::<Box<[u8]>>::into(i_sector_icc_1.clone()));
        c_message_buffer.extend_from_slice(&Into::<Box<[u8]>>::into(a1));
    }
    if let Some((a2, i_sector_icc_2)) = a2_i_sector_icc_2 {
        c_message_buffer.extend_from_slice(&Into::<Box<[u8]>>::into(i_sector_icc_2.clone()));
        c_message_buffer.extend_from_slice(&Into::<Box<[u8]>>::into(a2));
    }
    c_message_buffer.extend_from_slice(&Into::<Box<[u8]>>::into(pk_sector.clone()));
    c_message_buffer.extend_from_slice(ID_DSI);
    c_message_buffer.extend_from_slice(message);

    D::digest(&c_message_buffer)
}

pub struct SectorSpecificIdentifiers<C: PssCompatibleEccCurve> {
    i_sector_icc_1: C::Point,
    i_sector_icc_2: C::Point,
}

impl<C: PssCompatibleEccCurve> SectorSpecificIdentifiers<C> {
    pub fn new(i_sector_icc_1: C::Point, i_sector_icc_2: C::Point) -> Self {
        Self {
            i_sector_icc_1,
            i_sector_icc_2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EccPssSignature<C: PssCompatibleEccCurve> {
    c: C::Scalar,
    s1: C::Scalar,
    s2: C::Scalar,
    pseudonyms: (Option<C::Point>, Option<C::Point>),
}

impl<C: PssCompatibleEccCurve> Into<GenericPssSignature> for EccPssSignature<C> {
    fn into(self) -> GenericPssSignature {
        GenericPssSignature {
            c: self.c.into(),
            s1: self.s1.into(),
            s2: self.s2.into(),
            pseudonym1: self.pseudonyms.0.map(|pk| pk.into()),
            pseudonym2: self.pseudonyms.1.map(|pk| pk.into()),
        }
    }
}

impl<C: PssCompatibleEccCurve> TryFrom<GenericPssSignature> for EccPssSignature<C> {
    type Error = ();
    fn try_from(value: GenericPssSignature) -> Result<Self, Self::Error> {
        let c = C::Scalar::try_from(value.c).map_err(|_| ())?;
        let s1 = C::Scalar::try_from(value.s1).map_err(|_| ())?;
        let s2 = C::Scalar::try_from(value.s2).map_err(|_| ())?;

        let pseudonyms = (
            value
                .pseudonym1
                .map(|spoint| C::Point::try_from(spoint).map_err(|_| ()).unwrap()),
            value
                .pseudonym2
                .map(|spoint| C::Point::try_from(spoint).map_err(|_| ()).unwrap()),
        );
        Ok(EccPssSignature {
            c,
            s1,
            s2,
            pseudonyms,
        })
    }
}

impl<C: PssCompatibleEccCurve> PssSignature for EccPssSignature<C> {
    type PublicKey = C::Point;
    type Scalar = C::Scalar;

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

pub struct EccPssSigner<'a, C: PssCompatibleEccCurve> {
    sk_icc_1_u: &'a C::Scalar,
    sk_icc_2_u: &'a C::Scalar,
    pk_sector: &'a C::Point,
    pk_m: &'a C::Point,
    i_sector_icc_1: Option<C::Point>,
    i_sector_icc_2: Option<C::Point>,
}

impl<'a, C: PssCompatibleEccCurve> PssSigner for EccPssSigner<'a, C> {
    type PssSignature = EccPssSignature<C>;

    fn sign(&self, message: &[u8]) -> Self::PssSignature {
        let k1 = C::Scalar::random(&mut OsRng::default());
        let k2 = C::Scalar::random(&mut OsRng::default());

        let q1_part = self.pk_m.mul(&k2);
        let q1 = k1.to_point().add(&q1_part);

        let pseudonym1 = match self.i_sector_icc_1 {
            Some(ref pubkey) => Some((self.pk_sector.mul(&k1), pubkey)),
            None => None,
        };
        let pseudonym2 = match self.i_sector_icc_2 {
            Some(ref pubkey) => Some((self.pk_sector.mul(&k2), pubkey)),
            None => None,
        };

        let c_bin = signature_hash::<C, sha3::Keccak256>(
            &q1,
            pseudonym1,
            pseudonym2,
            &self.pk_sector,
            message,
        );
        let c = C::Scalar::from_hash(&c_bin);

        let s1 = k1.sub(&c.mul(self.sk_icc_1_u));
        let s2 = k2.sub(&c.mul(self.sk_icc_2_u));

        EccPssSignature {
            c,
            s1,
            s2,
            pseudonyms: (self.i_sector_icc_1.clone(), self.i_sector_icc_2.clone()),
        }
    }
}

pub struct EccIcc<C: PssCompatibleEccCurve> {
    gpk: EccGroupManagerPublicKey<C>,
    sk_icc_1_u: C::Scalar,
    sk_icc_2_u: C::Scalar,
}

impl<C: PssCompatibleEccCurve> Icc for EccIcc<C> {
    type GroupManagerPublicKey = EccGroupManagerPublicKey<C>;
    type SecretKey = C::Scalar;
    type SectorSpecificIdentifiers = SectorSpecificIdentifiers<C>;
    type PublicKey = C::Point;
    type Signer<'a> = EccPssSigner<'a, C>
        where C: 'a, <C as PssCompatibleEccCurve>::Scalar: 'a,
        <C as PssCompatibleEccCurve>::Point: 'a;

    fn new(
        gpk: Self::GroupManagerPublicKey,
        sk_icc_1_u: Self::SecretKey,
        sk_icc_2_u: Self::SecretKey,
    ) -> Self {
        let nym = Self {
            gpk,
            sk_icc_1_u,
            sk_icc_2_u,
        };
        assert!(nym.valid_for_gpk(&nym.gpk));
        nym
    }

    fn valid_for_gpk(&self, gpk: &Self::GroupManagerPublicKey) -> bool {
        let pk_icc_1_u = self.sk_icc_1_u.to_point();
        let pk_icc_2_u = gpk.pk_m.mul(&self.sk_icc_2_u);
        let result = pk_icc_1_u.add(&pk_icc_2_u);
        result == gpk.pk_icc
    }

    fn sector_identifiers(&self, pk_sector: &Self::PublicKey) -> Self::SectorSpecificIdentifiers {
        let i_sector_icc_1 = pk_sector.mul(&self.sk_icc_1_u);
        let i_sector_icc_2 = pk_sector.mul(&self.sk_icc_2_u);
        SectorSpecificIdentifiers::new(i_sector_icc_1, i_sector_icc_2)
    }

    fn signer<'a>(
        &'a self,
        pk_sector: &'a Self::PublicKey,
        use_identifier1: bool,
        use_identifier2: bool,
    ) -> <Self as Icc>::Signer<'a> {
        let identifiers = self.sector_identifiers(pk_sector);
        let (i_sector_icc_1, i_sector_icc_2) = match (use_identifier1, use_identifier2) {
            (true, true) => (
                Some(identifiers.i_sector_icc_1),
                Some(identifiers.i_sector_icc_2),
            ),
            (true, false) => (Some(identifiers.i_sector_icc_1), None),
            (false, true) => (None, Some(identifiers.i_sector_icc_2)),
            (false, false) => (None, None),
        };
        EccPssSigner {
            sk_icc_1_u: &self.sk_icc_1_u,
            sk_icc_2_u: &self.sk_icc_2_u,
            pk_sector: pk_sector,
            pk_m: &self.gpk.pk_m,
            i_sector_icc_1,
            i_sector_icc_2,
        }
    }

    fn from_generic_secret_key(
        secret_key: crate::GenericIccSecretKey,
        gpk: Self::GroupManagerPublicKey,
    ) -> Self {
        let sk_icc_1_u = C::Scalar::try_from(secret_key.sk_icc_1_u)
            .map_err(|_| ())
            .unwrap();
        let sk_icc_2_u = C::Scalar::try_from(secret_key.sk_icc_2_u)
            .map_err(|_| ())
            .unwrap();
        Self {
            gpk,
            sk_icc_1_u,
            sk_icc_2_u,
        }
    }
}

impl<C: PssCompatibleEccCurve> From<EccIcc<C>> for GenericIccSecretKey {
    fn from(value: EccIcc<C>) -> Self {
        Self {
            sk_icc_1_u: value.sk_icc_1_u.into(),
            sk_icc_2_u: value.sk_icc_2_u.into(),
        }
    }
}

#[derive(Debug)]
pub struct SectorKey<C: PssCompatibleEccCurve>(C::Scalar);

impl<C: PssCompatibleEccCurve> SectorKey<C> {
    pub fn public_key(&self) -> C::Point {
        self.0.to_point()
    }
}

pub struct EccGroupManager<C: PssCompatibleEccCurve> {
    sk_m: C::Scalar,
    sk_icc: C::Scalar,
    gpk: EccGroupManagerPublicKey<C>,
    sectors: Vec<(C::Point, Option<SectorKey<C>>)>,
}

impl<C: PssCompatibleEccCurve> GroupManager for EccGroupManager<C> {
    type SecretKey = C::Scalar;
    type PublicKey = C::Point;
    type GroupManagerPublicKey = EccGroupManagerPublicKey<C>;
    type Icc = EccIcc<C>;
    type Base = EccGroupManagerBaseIsImplicitInCurve;

    fn new(_g: Option<Self::Base>) -> Self {
        let sk_m = C::Scalar::random(&mut OsRng::default());
        let sk_icc = C::Scalar::random(&mut OsRng::default());
        Self::new_from_secret_parts(sk_m, sk_icc, _g)
    }

    fn new_from_secret_parts(
        sk_m: Self::SecretKey,
        sk_icc: Self::SecretKey,
        _g: Option<Self::Base>,
    ) -> Self {
        let pk_m = sk_m.to_point();
        let pk_icc = sk_icc.to_point();
        let gpk = EccGroupManagerPublicKey::new(pk_m, pk_icc, None);
        let sectors = Vec::new();
        Self {
            sk_m,
            sk_icc,
            gpk,
            sectors,
        }
    }

    fn renew_icc(&mut self) -> Self::SecretKey {
        let mut sk_icc = C::Scalar::random(&mut OsRng::default());
        self.gpk.pk_icc = sk_icc.to_point();
        std::mem::swap(&mut self.sk_icc, &mut sk_icc);
        sk_icc
    }

    fn new_icc(&self) -> EccIcc<C> {
        let sk_icc_2_u = C::Scalar::random(&mut OsRng::default());

        // TODO IF NOTHING WORKS THE REASON IS HERE!!!
        // SK_ICC_1 = SK_ICC - SK_M * SK_ICC_2
        let multiplication = self.sk_m.mul(&sk_icc_2_u);
        let sk_icc_1_u = self.sk_icc.sub(&multiplication);
        EccIcc::new(self.gpk.clone(), sk_icc_1_u, sk_icc_2_u)
    }

    fn new_sector(&mut self, deanonymizable: bool) -> Self::PublicKey {
        let key = SectorKey(C::Scalar::random(&mut OsRng::default()));
        let pubkey: C::Point = key.public_key();
        self.sectors.push((
            pubkey.clone(),
            match deanonymizable {
                true => Some(key),
                false => None,
            },
        ));
        pubkey
    }

    fn public_key(&self) -> &Self::GroupManagerPublicKey {
        &self.gpk
    }

    fn from_generic_secret_key(
        secret_key: crate::GenericGroupManagerPrivateKey,
        _g: Option<Box<[u8]>>,
    ) -> Self {
        Self::new_from_secret_parts(
            C::Scalar::try_from(secret_key.sk_m)
                .map_err(|_| ())
                .unwrap(),
            C::Scalar::try_from(secret_key.sk_icc)
                .map_err(|_| ())
                .unwrap(),
            None,
        )
    }
}

impl<C: PssCompatibleEccCurve> From<EccGroupManager<C>> for GenericGroupManagerPrivateKey {
    fn from(value: EccGroupManager<C>) -> Self {
        Self {
            sk_m: value.sk_m.into(),
            sk_icc: value.sk_icc.into(),
        }
    }
}

#[derive(Clone)]
pub struct EccGroupManagerPublicKey<C: PssCompatibleEccCurve> {
    pk_m: C::Point,
    pk_icc: C::Point,
}

pub struct EccGroupManagerBaseIsImplicitInCurve;

impl<C: PssCompatibleEccCurve> GroupManagerPublicKey for EccGroupManagerPublicKey<C> {
    type PublicKey = C::Point;
    type Signature = EccPssSignature<C>;
    type Base = PhantomData<EccGroupManagerBaseIsImplicitInCurve>;

    fn new(pk_m: Self::PublicKey, pk_icc: Self::PublicKey, _g: Option<Self::Base>) -> Self {
        Self { pk_m, pk_icc }
    }

    fn check_signature(
        &self,
        message: &[u8],
        pk_sector: &Self::PublicKey,
        signature: &Self::Signature,
    ) -> bool {
        self.recover_c(message, pk_sector, signature) == signature.c
    }

    fn from_generic_gpk(gpk: crate::GenericGroupManagerPublicKey, _g: Option<Box<[u8]>>) -> Self {
        let pk_m = C::Point::try_from(gpk.pk_m).map_err(|_| ()).unwrap();
        let pk_icc = C::Point::try_from(gpk.pk_icc).map_err(|_| ()).unwrap();
        Self { pk_icc, pk_m }
    }
}

impl<C: PssCompatibleEccCurve> From<EccGroupManagerPublicKey<C>> for GenericGroupManagerPublicKey {
    fn from(value: EccGroupManagerPublicKey<C>) -> Self {
        Self {
            pk_m: value.pk_m.into(),
            pk_icc: value.pk_icc.into(),
        }
    }
}

impl<C: PssCompatibleEccCurve> EccGroupManagerPublicKey<C> {
    pub(crate) fn recover_c(
        &self,
        message: &[u8],
        pk_sector: &C::Point,
        signature: &EccPssSignature<C>,
    ) -> C::Scalar {
        let q1s1 = self.pk_icc.mul(&signature.c);
        //let q1s2 = SecretKey::new(signature.s1.into::<ScalarPrimitive<C>>()).public_key().to_projective();
        let q1s2 = signature.s1.to_point();
        let q1s3 = self.pk_m.mul(&signature.s2);
        let q1 = q1s1.add(&q1s2).add(&q1s3);

        let pseudonym1 = match signature.pseudonyms.0 {
            Some(ref pubkey) => {
                let sector_c = pubkey.mul(&signature.c);
                let pk_s = pk_sector.mul(&signature.s1);
                let a1 = sector_c.add(&pk_s);
                Some((a1, pubkey))
            }
            None => None,
        };
        let pseudonym2 = match signature.pseudonyms.1 {
            Some(ref pubkey) => {
                let sector_c = pubkey.mul(&signature.c);
                let pk_s = pk_sector.mul(&signature.s2);
                let a2 = sector_c.add(&pk_s);
                Some((a2, pubkey))
            }
            None => None,
        };

        let c_bytes =
            signature_hash::<C, sha3::Keccak256>(&q1, pseudonym1, pseudonym2, pk_sector, message);
        let c = C::Scalar::from_hash(&c_bytes);

        c
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use crate::{
        ecc::{EccIcc, EccPssSignature, PssCompatibleEccCurve, Scalar}, rustcryptoecc::PssSecp256k1, GenericGroupManagerPublicKey, GenericPssSignature, GroupManager, GroupManagerPublicKey, Icc, PssSignature, PssSigner
    };
    use super::{EccGroupManager, EccGroupManagerPublicKey};

    const SIGN_MESSAGE: &[u8] = b"TEST MESSAGE";

    #[test]
    fn valid_keys() {
        let mut group_manager = EccGroupManager::new(None);
        let icc: EccIcc<PssSecp256k1> = group_manager.new_icc();
        assert!(icc.valid_for_gpk(group_manager.public_key()));

        let _ = group_manager.renew_icc();
        assert!(!icc.valid_for_gpk(group_manager.public_key()));
    }

    #[test]
    fn valid_signature() {
        let mut group_manager = EccGroupManager::new(None);
        let icc: EccIcc<PssSecp256k1> = group_manager.new_icc();
        let sector = group_manager.new_sector(false);

        let combinations = vec![(true, true), (true, false), (false, true), (false, false)];
        for (id1, id2) in combinations {
            let signer = icc.signer(&sector, id1, id2);
            let signature = signer.sign(SIGN_MESSAGE);
            let signature2 = signer.sign(SIGN_MESSAGE);
            
            assert!(group_manager
                .public_key()
                .check_signature(SIGN_MESSAGE, &sector, &signature));
            assert!(group_manager
                .public_key()
                .check_signature(SIGN_MESSAGE, &sector, &signature2));
            
            assert!(signature.c != signature2.c);
            assert!(signature.s1 != signature2.s1);
            assert!(signature.s2 != signature2.s2);

            if id1 {
                assert!(signature.pseudonym1().as_ref().unwrap() == signature2.pseudonym1().as_ref().unwrap());
            }
            if id2 {
                assert!(signature.pseudonym2().as_ref().unwrap() == signature2.pseudonym2().as_ref().unwrap());
            }
        }
    }

    #[test]
    fn invalid_signature() {
        let mut group_manager = EccGroupManager::new(None);
        let icc: EccIcc<PssSecp256k1> = group_manager.new_icc();
        let sector = group_manager.new_sector(false);

        let combinations = vec![(true, true), (true, false), (false, true), (false, false)];
        for (id1, id2) in combinations {
            let signer = icc.signer(&sector, id1, id2);
            let signature = signer.sign(SIGN_MESSAGE);
            fn tamper_with<C: PssCompatibleEccCurve>(
                signature: &mut EccPssSignature<C>,
                c: bool,
                s1: bool,
                s2: bool,
            ) {
                if c {
                    signature.c = signature.c.sub(&C::Scalar::random(&mut OsRng::default()));
                }
                if s1 {
                    signature.s1 = signature.s1.sub(&C::Scalar::random(&mut OsRng::default()));
                }
                if s2 {
                    signature.s2 = signature.s2.sub(&C::Scalar::random(&mut OsRng::default()));
                }
            }
            let combinations = vec![
                (true, true, true),
                (true, true, false),
                (true, false, true),
                (true, false, false),
                (false, true, true),
                (false, true, false),
                (false, false, true),
            ];
            for (c, s1, s2) in combinations {
                let mut signature_to_tamper_with = signature.clone();
                tamper_with(&mut signature_to_tamper_with, c, s1, s2);
                assert!(
                    !group_manager.public_key().check_signature(
                        SIGN_MESSAGE,
                        &sector,
                        &signature_to_tamper_with
                    ),
                    "signature was tampered with but still valid! c={} s1={} s2={}",
                    c,
                    s1,
                    s2
                );
            }
        }
    }

    #[test]
    fn sol_test_values() {
        let gpk = EccGroupManagerPublicKey::<PssSecp256k1>::from_generic_gpk(
            GenericGroupManagerPublicKey {
                pk_m: [
                    0x04, 0xb8, 0x0b, 0xc3, 0xa3, 0x02, 0x99, 0xf7, 0xe9, 0x64, 0x8c, 0x14, 0x1d,
                    0x93, 0xfb, 0x9d, 0x61, 0xad, 0x62, 0x57, 0xba, 0xfe, 0x1e, 0x5d, 0x93, 0xe4,
                    0xaf, 0xa8, 0xf3, 0x0e, 0x19, 0xe0, 0x0e, 0xd7, 0x01, 0x07, 0x2c, 0x1f, 0x7f,
                    0xa5, 0x64, 0x63, 0x14, 0x48, 0x69, 0xb6, 0x80, 0x6a, 0x1b, 0x3d, 0xd9, 0x50,
                    0xc9, 0xbd, 0x8e, 0x52, 0x6c, 0x6a, 0xdd, 0xd9, 0x9a, 0xb8, 0x55, 0x0b, 0x56,
                ]
                .into(),
                pk_icc: [
                    0x04, 0x53, 0x4c, 0x69, 0x71, 0x22, 0x44, 0x8f, 0x26, 0x79, 0x68, 0x06, 0x3d,
                    0x02, 0xd0, 0x1c, 0x0c, 0xf4, 0x41, 0x88, 0xd9, 0x6c, 0xd9, 0x95, 0x14, 0x60,
                    0x7d, 0xba, 0xd6, 0xf4, 0x95, 0x59, 0x50, 0x11, 0xc9, 0xf3, 0x56, 0xfb, 0xe8,
                    0x28, 0x1c, 0xb8, 0x33, 0xf2, 0x32, 0xe2, 0x15, 0xa7, 0xc8, 0x6a, 0x7c, 0xc5,
                    0xf3, 0xac, 0x10, 0x10, 0x45, 0xaf, 0x08, 0x48, 0xe9, 0x86, 0x81, 0xb7, 0xb8,
                ]
                .into(),
            },
            None,
        );
        let pk_sector_data: Box<[u8]> = [
            0x04, 0x8b, 0x3d, 0xee, 0xee, 0xe0, 0x7d, 0x19, 0x88, 0x0f, 0x86, 0x47, 0x72, 0xfc,
            0x54, 0xa7, 0x11, 0x20, 0x0c, 0x74, 0x86, 0xef, 0x40, 0xa3, 0x35, 0x7e, 0x57, 0x37,
            0xc8, 0x37, 0xb2, 0xca, 0xd1, 0x7a, 0x08, 0x73, 0xe0, 0x5a, 0xec, 0x94, 0x40, 0x06,
            0xbe, 0xe4, 0xc1, 0x01, 0x20, 0x79, 0x88, 0x8c, 0x36, 0x3a, 0x6a, 0xac, 0xe0, 0xe6,
            0x51, 0x92, 0x2f, 0xfa, 0xe6, 0xf1, 0x16, 0xff, 0x08,
        ]
        .into();
        let pk_sector = pk_sector_data.try_into().unwrap();
        let signature = GenericPssSignature {
            c: [
                0xdd, 0xde, 0xdb, 0xb7, 0x38, 0x09, 0xfa, 0x73, 0x13, 0x2c, 0xe0, 0xd9, 0x46, 0xbf,
                0xde, 0x58, 0x9c, 0xcc, 0x04, 0x8a, 0xe3, 0xb8, 0x60, 0xab, 0x31, 0x48, 0x40, 0x93,
                0x8d, 0xa9, 0x12, 0xa8,
            ]
            .into(),
            s1: [
                0x8c, 0x00, 0xd3, 0x9c, 0x38, 0x37, 0x0e, 0x8a, 0xd9, 0x20, 0x6d, 0x32, 0xdd, 0x0d,
                0xf3, 0x20, 0xa2, 0x80, 0x34, 0x0e, 0x7f, 0x05, 0x0a, 0x35, 0x8e, 0xaf, 0xef, 0x39,
                0x9a, 0x29, 0x73, 0xc7,
            ]
            .into(),
            s2: [
                0xe5, 0x05, 0x41, 0x06, 0xe0, 0x49, 0x79, 0x5c, 0xc3, 0x12, 0x62, 0x20, 0xd9, 0x3d,
                0x77, 0x3e, 0xd1, 0x7c, 0x23, 0xca, 0x9a, 0x24, 0x09, 0xfb, 0x6b, 0x4f, 0x27, 0xa6,
                0x22, 0xf9, 0x4b, 0xd2,
            ]
            .into(),
            pseudonym1: Some(
                [
                    0x03, 0x70, 0xaf, 0xa9, 0x71, 0x24, 0x73, 0x33, 0x83, 0x66, 0xd0, 0x03, 0x7e,
                    0x10, 0xd1, 0xd1, 0xe9, 0xdd, 0x56, 0xa4, 0x37, 0x72, 0x41, 0x4e, 0xd7, 0x31,
                    0xc2, 0x90, 0x69, 0x3e, 0xf5, 0x3a, 0x44,
                ]
                .into(),
            ),
            pseudonym2: Some(
                [
                    0x02, 0x93, 0x54, 0xda, 0x7c, 0x85, 0xf6, 0x3b, 0xe2, 0xd1, 0x09, 0x30, 0x17,
                    0x13, 0x84, 0x89, 0x75, 0x33, 0x4b, 0x4d, 0xbf, 0x03, 0xee, 0xab, 0x4b, 0x9d,
                    0x22, 0x18, 0xbd, 0x97, 0xb3, 0xf9, 0xc2,
                ]
                .into(),
            ),
        }
        .try_into()
        .unwrap();
        let message = [0x00, 0x01, 0x02];
        assert!(gpk.check_signature(&message, &pk_sector, &signature));
    }
}
