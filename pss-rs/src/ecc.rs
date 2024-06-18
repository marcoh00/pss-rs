use crate::{mul_mod, GenericGroupManagerPrivateKey, GenericGroupManagerPublicKey, GenericIccSecretKey, GenericPssSignature, GenericPublicKey, GroupManager, GroupManagerPublicKey, Icc, PssSignature, PssSigner};

use crypto_bigint::{generic_array::{sequence::GenericSequence, GenericArray}, rand_core::OsRng, ArrayEncoding, ConcatMixed, NonZero, Uint};
use elliptic_curve::{point::PointCompression, sec1::{FromEncodedPoint, ModulusSize}, Curve, CurveArithmetic, PublicKey, SecretKey};
use k256::elliptic_curve::{sec1::ToEncodedPoint, PrimeField, ScalarPrimitive};
use sha3::Digest;
use std::{marker::PhantomData, ops::{Add, Mul, Rem, Sub}};

const ID_DSI: &[u8] = b"ECC-KECCAK256";

fn signature_hash<C: Curve + CurveArithmetic, D: Digest>(q: &C::AffinePoint, a1_i_sector_icc_1: Option<(C::AffinePoint, &PublicKey<C>)>, a2_i_sector_icc_2: Option<(C::AffinePoint, &PublicKey<C>)>, pk_sector: &PublicKey<C>, message: &[u8]) -> GenericArray<u8, D::OutputSize>
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    let mut c_message_buffer = Vec::new();
    c_message_buffer.extend_from_slice(q.to_encoded_point(false).as_bytes());
    if let Some((a1, i_sector_icc_1)) = a1_i_sector_icc_1 {
        c_message_buffer.extend_from_slice(i_sector_icc_1.to_encoded_point(false).as_bytes());
        c_message_buffer.extend_from_slice(a1.to_encoded_point(false).as_bytes());
    }
    if let Some((a2, i_sector_icc_2)) = a2_i_sector_icc_2 {
        c_message_buffer.extend_from_slice(i_sector_icc_2.to_encoded_point(false).as_bytes());
        c_message_buffer.extend_from_slice(a2.to_encoded_point(false).as_bytes());
    }
    c_message_buffer.extend_from_slice(pk_sector.to_encoded_point(false).as_bytes());
    c_message_buffer.extend_from_slice(ID_DSI);
    c_message_buffer.extend_from_slice(message);

    D::digest(&c_message_buffer)
}

fn hash2curve<C: CurveArithmetic>(hash: &[u8]) -> C::Scalar {
    let array_fitting_length = GenericArray::generate(|idx| {
        if idx < hash.len() {
            hash[idx]
        } else {
            0
        }
    });
    // According to BSI TR-03111 3.1.3 Conversion between Field Elements and Octet Strings:
    // "An octet string X is converted to a field element by applying the conversion function OS2I as described in Section 3.1.2 and reducing the output modulo p, i.e. OS2FE(X) = OS2I(X) mod p"
    let num = <C::Uint as ArrayEncoding>::from_be_byte_array(array_fitting_length)
        .rem(NonZero::new(C::ORDER).unwrap());
    C::Scalar::from(ScalarPrimitive::new(num).unwrap())
}

impl<C: Curve + CurveArithmetic + PointCompression> From<PublicKey<C>> for GenericPublicKey
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    fn from(value: PublicKey<C>) -> Self {
        GenericPublicKey(value.to_encoded_point(false).as_bytes().into())
    }
}

impl<C: Curve + CurveArithmetic> TryFrom<GenericPublicKey> for PublicKey<C>
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    type Error = elliptic_curve::Error;

    fn try_from(value: GenericPublicKey) -> Result<Self, Self::Error> {
        PublicKey::from_sec1_bytes(&value.0)
    }
}

pub struct SectorSpecificIdentifiers<C: Curve + CurveArithmetic> {
    i_sector_icc_1: PublicKey<C>,
    i_sector_icc_2: PublicKey<C>
}

impl<C: Curve + CurveArithmetic> SectorSpecificIdentifiers<C> {
    pub fn new(i_sector_icc_1: PublicKey<C>, i_sector_icc_2: PublicKey<C>) -> Self {
        Self { i_sector_icc_1, i_sector_icc_2 }
    }
}

#[derive(Debug, Clone)]
pub struct EccPssSignature<C: Curve + CurveArithmetic>
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    c: C::Scalar,
    s1: C::Scalar,
    s2: C::Scalar,
    pseudonyms: (Option<PublicKey<C>>, Option<PublicKey<C>>)
}

impl<C: Curve + CurveArithmetic> Into<GenericPssSignature> for EccPssSignature<C>
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    fn into(self) -> GenericPssSignature {
        GenericPssSignature {
            c: self.c.to_repr().as_slice().into(),
            s1: self.s1.to_repr().as_slice().into(),
            s2: self.s2.to_repr().as_slice().into(),
            pseudonym1: self.pseudonyms.0.map(|pk| pk.to_encoded_point(true).to_bytes()),
            pseudonym2: self.pseudonyms.1.map(|pk| pk.to_encoded_point(true).to_bytes())
            
        }
    }
}

impl<C: Curve + CurveArithmetic> TryFrom<GenericPssSignature> for EccPssSignature<C>
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    type Error = ();
    fn try_from(value: GenericPssSignature) -> Result<Self, Self::Error> {
        let c = C::Scalar::from_repr(GenericArray::clone_from_slice(&value.c)).unwrap();
        let s1 = C::Scalar::from_repr(GenericArray::clone_from_slice(&value.s1)).unwrap();
        let s2 = C::Scalar::from_repr(GenericArray::clone_from_slice(&value.s2)).unwrap();

        let pseudonyms = (
            value.pseudonym1.map(|spoint| PublicKey::from_sec1_bytes(spoint.as_ref()).unwrap()),
            value.pseudonym2.map(|spoint| PublicKey::from_sec1_bytes(spoint.as_ref()).unwrap())
        );
        Ok(EccPssSignature {
            c, s1, s2, pseudonyms
        })
    }
}

impl<C: Curve + CurveArithmetic + PointCompression> PssSignature for EccPssSignature<C>
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    type PublicKey = PublicKey<C>;
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

#[derive(Debug)]
pub struct EccPssSigner<'a, C: Curve + CurveArithmetic>
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize  {
    sk_icc_1_u: &'a SecretKey<C>,
    sk_icc_2_u: &'a SecretKey<C>,
    pk_sector: &'a PublicKey<C>,
    pk_m: &'a PublicKey<C>,
    i_sector_icc_1: Option<PublicKey<C>>,
    i_sector_icc_2: Option<PublicKey<C>>,
}

impl<'a, C: Curve + CurveArithmetic + PointCompression> PssSigner for EccPssSigner<'a, C>
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    type PssSignature = EccPssSignature<C>;
    
    fn sign(&self, message: &[u8]) -> Self::PssSignature {
        let k1: SecretKey<C> = SecretKey::random(&mut OsRng::default());
        let k2: SecretKey<C> = SecretKey::random(&mut OsRng::default());

        let k1_scalar: C::Scalar = k1.as_scalar_primitive().to_owned().into();
        let k2_scalar: C::Scalar = k2.as_scalar_primitive().to_owned().into();

        let q1_part: C::ProjectivePoint = self.pk_m.to_projective().mul(&k2_scalar);
        let q1: C::AffinePoint = k1.public_key().to_projective().add(&q1_part).into();

        let pk_sector_proj = self.pk_sector.to_projective();

        let pseudonym1 = match self.i_sector_icc_1 {
            Some(ref pubkey) => Some((pk_sector_proj.mul(&k1_scalar).into(), pubkey)),
            None => None
        };
        let pseudonym2 = match self.i_sector_icc_2 {
            Some(ref pubkey) => Some((pk_sector_proj.mul(&k2_scalar).into(), pubkey)),
            None => None
        };

        let c_bin = signature_hash::<C, sha3::Keccak256>(&q1, pseudonym1, pseudonym2, &self.pk_sector, message);
        let c: C::Scalar = hash2curve::<C>(&c_bin);

        let sk_icc_1_u_scalar: C::Scalar = self.sk_icc_1_u.as_scalar_primitive().to_owned().into();
        let sk_icc_2_u_scalar: C::Scalar = self.sk_icc_2_u.as_scalar_primitive().to_owned().into();

        let s1 = k1_scalar.sub(c.mul(sk_icc_1_u_scalar));
        let s2 = k2_scalar.sub(c.mul(sk_icc_2_u_scalar));

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
pub struct EccIcc<C: Curve + CurveArithmetic>
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    gpk: EccGroupManagerPublicKey<C>,
    sk_icc_1_u: SecretKey<C>,
    sk_icc_2_u: SecretKey<C>
}

impl<C: Curve + CurveArithmetic> Icc for EccIcc<C>
where C: PointCompression, C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    type GroupManagerPublicKey = EccGroupManagerPublicKey<C>;
    type SecretKey = SecretKey<C>;
    type SectorSpecificIdentifiers = SectorSpecificIdentifiers<C>;
    type PublicKey = PublicKey<C>;
    type Signer<'a> = EccPssSigner<'a, C>;

    fn new(gpk: Self::GroupManagerPublicKey, sk_icc_1_u: Self::SecretKey, sk_icc_2_u: Self::SecretKey) -> Self {
        let nym = Self { gpk, sk_icc_1_u, sk_icc_2_u };
        assert!(nym.valid_for_gpk(&nym.gpk));
        nym
    }

    fn valid_for_gpk(&self, gpk: &Self::GroupManagerPublicKey) -> bool {
        let sk_icc_2_u_scalar: C::Scalar = self.sk_icc_2_u.as_scalar_primitive().to_owned().into();
        let pk_icc_1_u = self.sk_icc_1_u.public_key().to_projective();
        let pk_icc_2_u = gpk.pk_m.to_projective().mul(&sk_icc_2_u_scalar);
        let result = pk_icc_1_u + pk_icc_2_u;
        &result.into() == gpk.pk_icc.as_affine()
    }

    fn sector_identifiers(&self, pk_sector: &Self::PublicKey) -> Self::SectorSpecificIdentifiers {
        let sk_icc_1_u_scalar: C::Scalar = self.sk_icc_1_u.as_scalar_primitive().to_owned().into();
        let sk_icc_2_u_scalar: C::Scalar = self.sk_icc_2_u.as_scalar_primitive().to_owned().into();
        let i_sector_icc_1 = PublicKey::from_affine(pk_sector.to_projective().mul(&sk_icc_1_u_scalar).into()).unwrap();
        let i_sector_icc_2 = PublicKey::from_affine(pk_sector.to_projective().mul(&sk_icc_2_u_scalar).into()).unwrap();
        SectorSpecificIdentifiers::new(i_sector_icc_1, i_sector_icc_2)
    }

    fn signer<'a>(&'a self, pk_sector: &'a Self::PublicKey, use_identifier1: bool, use_identifier2: bool) -> <Self as Icc>::Signer<'a> {
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


impl<C: Curve + CurveArithmetic> From<EccIcc<C>> for GenericIccSecretKey
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    fn from(value: EccIcc<C>) -> Self {
        Self { sk_icc_1_u: value.sk_icc_1_u.to_bytes().as_slice().into(), sk_icc_2_u: value.sk_icc_2_u.to_bytes().as_slice().into() }
    }
}

#[derive(Debug)]
pub struct SectorKey<C: Curve + CurveArithmetic>(SecretKey<C>);

impl<C: Curve + CurveArithmetic> SectorKey<C> {
    pub fn public_key(&self) -> PublicKey<C> {
        self.0.public_key()
    }
}

#[derive(Debug)]
pub struct EccGroupManager<const LIMBS: usize, const WIDE_LIMBS: usize, C: Curve<Uint = Uint<LIMBS>>>
where C: Curve + CurveArithmetic, Uint<LIMBS>: ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>> {
    sk_m: SecretKey<C>,
    sk_icc: SecretKey<C>,
    gpk: EccGroupManagerPublicKey<C>,
    sectors: Vec<(PublicKey<C>, Option<SectorKey<C>>)>
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, C: Curve<Uint = Uint<LIMBS>>> GroupManager for EccGroupManager<LIMBS, WIDE_LIMBS, C>
where C: Curve + CurveArithmetic + PointCompression, C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize, Uint<LIMBS>: ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>> {
    type SecretKey = SecretKey<C>;
    type PublicKey = PublicKey<C>;
    type GroupManagerPublicKey = EccGroupManagerPublicKey<C>;
    type Icc = EccIcc<C>;
    type Base = EccGroupManagerBaseIsImplicitInCurve;
    
    fn new(_g: Option<Self::Base>) -> Self {
        let sk_m = SecretKey::random(&mut OsRng::default());
        let sk_icc = SecretKey::random(&mut OsRng::default());
        Self::new_from_secret_parts(sk_m, sk_icc, _g)
    }

    fn new_from_secret_parts(sk_m: Self::SecretKey, sk_icc: Self::SecretKey, _g: Option<Self::Base>) -> Self {
        let pk_m = sk_m.public_key();
        let pk_icc = sk_icc.public_key();
        let gpk = EccGroupManagerPublicKey::new(pk_m, pk_icc, None);
        let sectors = Vec::new();
        Self { sk_m, sk_icc, gpk, sectors }
    }

    fn renew_icc(&mut self) -> Self::SecretKey {
        let mut sk_icc = SecretKey::random(&mut OsRng::default());
        self.gpk.pk_icc = sk_icc.public_key();
        std::mem::swap(&mut self.sk_icc, &mut sk_icc);
        sk_icc
    }

    fn new_icc(&self) -> EccIcc<C> {
        let sk_icc_2_u = SecretKey::random(&mut OsRng::default());
        let sk_icc_2_u_scalar = sk_icc_2_u.as_scalar_primitive().as_uint();
        let sk_m_scalar = self.sk_m.as_scalar_primitive().as_uint();
        let sk_icc_scalar = self.sk_icc.as_scalar_primitive();

        // SK_ICC_1 = SK_ICC - SK_M * SK_ICC_2
        let multiplication = ScalarPrimitive::new(mul_mod(&sk_m_scalar, &sk_icc_2_u_scalar, &C::ORDER)).unwrap();
        let sk_icc_1_u_scalar = sk_icc_scalar.sub(&multiplication);
        let sk_icc_1_u = SecretKey::new(sk_icc_1_u_scalar);
        EccIcc::new(self.gpk.clone(), sk_icc_1_u, sk_icc_2_u)
    }

    fn new_sector(&mut self, deanonymizable: bool) -> Self::PublicKey {
        let key = SectorKey(SecretKey::random(&mut OsRng::default()));
        let pubkey = key.public_key();
        self.sectors.push((pubkey.clone(), match deanonymizable {
            true => Some(key),
            false => None
        }));
        pubkey
    }

    fn public_key(&self) -> &Self::GroupManagerPublicKey {
        &self.gpk
    }
    
    fn from_generic_secret_key(secret_key: crate::GenericGroupManagerPrivateKey, _g: Option<Box<[u8]>>) -> Self {
        Self::new_from_secret_parts(SecretKey::from_slice(&secret_key.sk_m).unwrap(), SecretKey::from_slice(&secret_key.sk_icc).unwrap(), None)
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, C: Curve<Uint = Uint<LIMBS>>> From<EccGroupManager<LIMBS, WIDE_LIMBS, C>> for GenericGroupManagerPrivateKey
where C: Curve + CurveArithmetic, Uint<LIMBS>: ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>> {
    fn from(value: EccGroupManager<LIMBS, WIDE_LIMBS, C>) -> Self {
        Self {
            sk_m: value.sk_m.to_bytes().as_slice().into(),
            sk_icc: value.sk_icc.to_bytes().as_slice().into()
        }
    }
}

#[derive(Debug, Clone)]
pub struct EccGroupManagerPublicKey<C: Curve + CurveArithmetic> {
    pk_m: PublicKey<C>,
    pk_icc: PublicKey<C>
}

pub struct EccGroupManagerBaseIsImplicitInCurve();

impl<C: Curve + CurveArithmetic> GroupManagerPublicKey for EccGroupManagerPublicKey<C>
where C: PointCompression, C::FieldBytesSize: ModulusSize, C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C> {
    type PublicKey = PublicKey<C>;
    type Signature = EccPssSignature<C>;
    type Base = PhantomData<EccGroupManagerBaseIsImplicitInCurve>;

    fn new(pk_m: Self::PublicKey, pk_icc: Self::PublicKey, _g: Option<Self::Base>) -> Self {
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

impl<C: Curve + CurveArithmetic> From<EccGroupManagerPublicKey<C>> for GenericGroupManagerPublicKey
where C: PointCompression, C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    fn from(value: EccGroupManagerPublicKey<C>) -> Self {
        Self {
            pk_m: value.pk_m.to_encoded_point(false).as_bytes().into(),
            pk_icc: value.pk_icc.to_encoded_point(false).as_bytes().into()
        }
    }
}

impl<C: Curve + CurveArithmetic> EccGroupManagerPublicKey<C>
where C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    pub(crate) fn recover_c(&self, message: &[u8], pk_sector: &PublicKey<C>, signature: &EccPssSignature<C>) -> C::Scalar {
        let q1s1 = self.pk_icc.to_projective().mul(signature.c);
        //let q1s2 = SecretKey::new(signature.s1.into::<ScalarPrimitive<C>>()).public_key().to_projective();
        let s1_scalar: ScalarPrimitive<C> = signature.s1.into();
        let q1s2 = SecretKey::new(s1_scalar).public_key().to_projective();
        let q1s3 = self.pk_m.to_projective().mul(signature.s2);
        let q1: C::AffinePoint = q1s1.add(&q1s2).add(&q1s3).into();

        let pseudonym1 = match signature.pseudonyms.0 {
            Some(ref pubkey) => {
                let sector_c = pubkey.to_projective().mul(signature.c);
                let pk_s = pk_sector.to_projective().mul(signature.s1);
                let a1: C::AffinePoint = sector_c.add(&pk_s).into();
                Some((a1, pubkey))
            },
            None => None,
        };
        let pseudonym2 = match signature.pseudonyms.1 {
            Some(ref pubkey) => {
                let sector_c = pubkey.to_projective().mul(signature.c);
                let pk_s = pk_sector.to_projective().mul(signature.s2);
                let a2: C::AffinePoint = sector_c.add(&pk_s).into();
                Some((a2, pubkey))
            },
            None => None,
        };

        let c_bytes = signature_hash::<C, sha3::Keccak256>(&q1, pseudonym1, pseudonym2, pk_sector, message);
        let c = hash2curve::<C>(&c_bytes);

        c
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Sub;

    use elliptic_curve::{sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint}, Curve, CurveArithmetic, ScalarPrimitive};
    use k256::Secp256k1;

    use crate::{ecc::{EccIcc, EccPssSignature}, GenericGroupManagerPublicKey, GenericPssSignature, GenericPublicKey, GroupManager, GroupManagerPublicKey, Icc, PssSigner};

    use super::{EccGroupManager, EccGroupManagerPublicKey};

    const SIGN_MESSAGE: &[u8] = b"TEST MESSAGE";

    #[test]
    fn valid_keys() {
        let mut group_manager = EccGroupManager::new(None);
        let icc: EccIcc<Secp256k1> = group_manager.new_icc();
        assert!(icc.valid_for_gpk(group_manager.public_key()));

        let _ = group_manager.renew_icc();
        assert!(!icc.valid_for_gpk(group_manager.public_key()));
    }

    #[test]
    fn valid_signature() {
        let mut group_manager = EccGroupManager::new(None);
        let icc: EccIcc<Secp256k1> = group_manager.new_icc();
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
        let mut group_manager = EccGroupManager::new(None);
        let icc: EccIcc<Secp256k1> = group_manager.new_icc();
        let sector = group_manager.new_sector(false);

        let combinations = vec![(true, true), (true, false), (false, true), (false, false)];
        for (id1, id2) in combinations {
            let signer = icc.signer(&sector, id1, id2);
            let signature = signer.sign(SIGN_MESSAGE);
            fn tamper_with<C: Curve + CurveArithmetic>(signature: &mut EccPssSignature<C>, c: bool, s1: bool, s2: bool)
            where C::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
                if c {
                    signature.c = signature.c.sub(&ScalarPrimitive::new(C::Uint::from(1u64)).unwrap().into());
                }
                if s1 {
                    signature.s1 = signature.s1.sub(&ScalarPrimitive::new(C::Uint::from(1u64)).unwrap().into());
                }
                if s2 {
                    signature.s2 = signature.s2.sub(&ScalarPrimitive::new(C::Uint::from(1u64)).unwrap().into());
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

    #[test]
    fn sol_test_values() {
        let gpk = EccGroupManagerPublicKey::<Secp256k1>::from_generic_gpk(GenericGroupManagerPublicKey {
            pk_m: [0x04, 0xb8, 0x0b, 0xc3, 0xa3, 0x02, 0x99, 0xf7, 0xe9, 0x64, 0x8c, 0x14, 0x1d, 0x93, 0xfb, 0x9d, 0x61, 0xad, 0x62, 0x57, 0xba, 0xfe, 0x1e, 0x5d, 0x93, 0xe4, 0xaf, 0xa8, 0xf3, 0x0e, 0x19, 0xe0, 0x0e, 0xd7, 0x01, 0x07, 0x2c, 0x1f, 0x7f, 0xa5, 0x64, 0x63, 0x14, 0x48, 0x69, 0xb6, 0x80, 0x6a, 0x1b, 0x3d, 0xd9, 0x50, 0xc9, 0xbd, 0x8e, 0x52, 0x6c, 0x6a, 0xdd, 0xd9, 0x9a, 0xb8, 0x55, 0x0b, 0x56].into(),
            pk_icc: [0x04, 0x53, 0x4c, 0x69, 0x71, 0x22, 0x44, 0x8f, 0x26, 0x79, 0x68, 0x06, 0x3d, 0x02, 0xd0, 0x1c, 0x0c, 0xf4, 0x41, 0x88, 0xd9, 0x6c, 0xd9, 0x95, 0x14, 0x60, 0x7d, 0xba, 0xd6, 0xf4, 0x95, 0x59, 0x50, 0x11, 0xc9, 0xf3, 0x56, 0xfb, 0xe8, 0x28, 0x1c, 0xb8, 0x33, 0xf2, 0x32, 0xe2, 0x15, 0xa7, 0xc8, 0x6a, 0x7c, 0xc5, 0xf3, 0xac, 0x10, 0x10, 0x45, 0xaf, 0x08, 0x48, 0xe9, 0x86, 0x81, 0xb7, 0xb8].into()
        }, None);
        let pk_sector = GenericPublicKey(
            [0x04, 0x8b, 0x3d, 0xee, 0xee, 0xe0, 0x7d, 0x19, 0x88, 0x0f, 0x86, 0x47, 0x72, 0xfc, 0x54, 0xa7, 0x11, 0x20, 0x0c, 0x74, 0x86, 0xef, 0x40, 0xa3, 0x35, 0x7e, 0x57, 0x37, 0xc8, 0x37, 0xb2, 0xca, 0xd1, 0x7a, 0x08, 0x73, 0xe0, 0x5a, 0xec, 0x94, 0x40, 0x06, 0xbe, 0xe4, 0xc1, 0x01, 0x20, 0x79, 0x88, 0x8c, 0x36, 0x3a, 0x6a, 0xac, 0xe0, 0xe6, 0x51, 0x92, 0x2f, 0xfa, 0xe6, 0xf1, 0x16, 0xff, 0x08].into()
        ).try_into().unwrap();
        let signature = GenericPssSignature {
            c: [0xdd, 0xde, 0xdb, 0xb7, 0x38, 0x09, 0xfa, 0x73, 0x13, 0x2c, 0xe0, 0xd9, 0x46, 0xbf, 0xde, 0x58, 0x9c, 0xcc, 0x04, 0x8a, 0xe3, 0xb8, 0x60, 0xab, 0x31, 0x48, 0x40, 0x93, 0x8d, 0xa9, 0x12, 0xa8].into(),
            s1: [0x8c, 0x00, 0xd3, 0x9c, 0x38, 0x37, 0x0e, 0x8a, 0xd9, 0x20, 0x6d, 0x32, 0xdd, 0x0d, 0xf3, 0x20, 0xa2, 0x80, 0x34, 0x0e, 0x7f, 0x05, 0x0a, 0x35, 0x8e, 0xaf, 0xef, 0x39, 0x9a, 0x29, 0x73, 0xc7].into(),
            s2: [0xe5, 0x05, 0x41, 0x06, 0xe0, 0x49, 0x79, 0x5c, 0xc3, 0x12, 0x62, 0x20, 0xd9, 0x3d, 0x77, 0x3e, 0xd1, 0x7c, 0x23, 0xca, 0x9a, 0x24, 0x09, 0xfb, 0x6b, 0x4f, 0x27, 0xa6, 0x22, 0xf9, 0x4b, 0xd2].into(),
            pseudonym1: Some([0x03, 0x70, 0xaf, 0xa9, 0x71, 0x24, 0x73, 0x33, 0x83, 0x66, 0xd0, 0x03, 0x7e, 0x10, 0xd1, 0xd1, 0xe9, 0xdd, 0x56, 0xa4, 0x37, 0x72, 0x41, 0x4e, 0xd7, 0x31, 0xc2, 0x90, 0x69, 0x3e, 0xf5, 0x3a, 0x44].into()),
            pseudonym2: Some([0x02, 0x93, 0x54, 0xda, 0x7c, 0x85, 0xf6, 0x3b, 0xe2, 0xd1, 0x09, 0x30, 0x17, 0x13, 0x84, 0x89, 0x75, 0x33, 0x4b, 0x4d, 0xbf, 0x03, 0xee, 0xab, 0x4b, 0x9d, 0x22, 0x18, 0xbd, 0x97, 0xb3, 0xf9, 0xc2].into())
        }.try_into().unwrap();
        let message = [0x00, 0x01, 0x02];
        assert!(gpk.check_signature(&message, &pk_sector, &signature));
    }
}