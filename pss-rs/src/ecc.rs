use crate::{
    GenericGroupManagerPrivateKey, GenericGroupManagerPublicKey, GenericIccSecretKey,
    GenericPssSignature, GroupManager, GroupManagerPublicKey, Icc, PssSignature, PssSigner,
};
use std::fmt::{Debug, Formatter};

use crypto_bigint::{generic_array::GenericArray, rand_core::OsRng};

use rand_core::CryptoRngCore;
use sha3::Digest;
use std::marker::PhantomData;

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
    const ID_DSI: &'static [u8];
    type Curve;
    type Scalar: Scalar<Self::Curve, Point = Self::Point>
        + Clone
        + TryFrom<Box<[u8]>, Error: Debug>
        + Into<Box<[u8]>>
        + PartialEq;
    type Point: Point<Self::Curve, Scalar = Self::Scalar>
        + Clone
        + TryFrom<Box<[u8]>, Error: Debug>
        + Into<Box<[u8]>>
        + PartialEq;
}

pub struct SerializationError;

impl Debug for SerializationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("Error serializing")
    }
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
    c_message_buffer.extend_from_slice(C::ID_DSI);
    c_message_buffer.extend_from_slice(message);

    D::digest(&c_message_buffer)
}

pub struct SectorSpecificIdentifiers<C: PssCompatibleEccCurve> {
    pub(crate) i_sector_icc_1: C::Point,
    pub(crate) i_sector_icc_2: C::Point,
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
    pub(crate) c: C::Scalar,
    pub(crate) s1: C::Scalar,
    pub(crate) s2: C::Scalar,
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
pub(crate) mod tests {
    use super::EccGroupManager;
    use crate::{
        ecc::{EccIcc, EccPssSignature, PssCompatibleEccCurve, Scalar},
        GroupManager, GroupManagerPublicKey, Icc, PssSignature, PssSigner,
    };
    use rand_core::OsRng;

    const SIGN_MESSAGE: &[u8] = b"TEST MESSAGE";

    pub(crate) fn valid_keys<C: PssCompatibleEccCurve>() {
        let mut group_manager = EccGroupManager::new(None);
        let icc: EccIcc<C> = group_manager.new_icc();
        assert!(icc.valid_for_gpk(group_manager.public_key()));

        let _ = group_manager.renew_icc();
        assert!(!icc.valid_for_gpk(group_manager.public_key()));
    }

    pub(crate) fn valid_signature<C: PssCompatibleEccCurve>() {
        let mut group_manager = EccGroupManager::new(None);
        let icc: EccIcc<C> = group_manager.new_icc();
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
                assert!(
                    signature.pseudonym1().as_ref().unwrap()
                        == signature2.pseudonym1().as_ref().unwrap()
                );
            }
            if id2 {
                assert!(
                    signature.pseudonym2().as_ref().unwrap()
                        == signature2.pseudonym2().as_ref().unwrap()
                );
            }
        }
    }

    pub(crate) fn invalid_signature<C: PssCompatibleEccCurve>() {
        let mut group_manager = EccGroupManager::new(None);
        let icc: EccIcc<C> = group_manager.new_icc();
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
}
