use crate::ecc::{Point, PssCompatibleEccCurve, Scalar, SerializationError};

use crypto_bigint::{
    generic_array::{sequence::GenericSequence, GenericArray},
    ArrayEncoding, NonZero,
};
use elliptic_curve::{
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize},
    CurveArithmetic, NonZeroScalar, PublicKey, SecretKey,
};
use group::{Curve as GroupCurve, Group};
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField, ScalarPrimitive},
    Secp256k1,
};
use rand_core::CryptoRngCore;
use std::ops::{Add, Mul, Rem, Sub};

#[derive(Clone, PartialEq)]
pub struct RustCryptoPoint<C: CurveArithmetic>(C::AffinePoint);

#[derive(Clone, PartialEq)]
pub struct RustCryptoScalar<C: CurveArithmetic>(C::Scalar);

impl<C: CurveArithmetic> Scalar<C> for RustCryptoScalar<C> {
    type Point = RustCryptoPoint<C>;

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        let nzscalar: NonZeroScalar<C> = SecretKey::random(rng).to_nonzero_scalar();
        let scalar_ref: &C::Scalar = nzscalar.as_ref();
        Self(scalar_ref.to_owned())
    }

    fn add(&self, other: &Self) -> Self {
        Self(self.0.add(other.0))
    }

    fn sub(&self, other: &Self) -> Self {
        Self(self.0.sub(other.0))
    }

    fn mul(&self, other: &Self) -> Self {
        Self(self.0.mul(other.0))
    }

    fn to_point(&self) -> Self::Point {
        let nzscalar: NonZeroScalar<C> = NonZeroScalar::new(self.0).unwrap();
        let pk: PublicKey<C> = PublicKey::from_secret_scalar(&nzscalar);
        RustCryptoPoint(pk.as_affine().to_owned())
    }

    fn from_hash(hash: &[u8]) -> Self {
        let array_fitting_length =
            GenericArray::generate(|idx| if idx < hash.len() { hash[idx] } else { 0 });
        // According to BSI TR-03111 3.1.3 Conversion between Field Elements and Octet Strings:
        // "An octet string X is converted to a field element by applying the conversion function OS2I as described in Section 3.1.2 and reducing the output modulo p, i.e. OS2FE(X) = OS2I(X) mod p"
        let num = <C::Uint as ArrayEncoding>::from_be_byte_array(array_fitting_length)
            .rem(NonZero::new(C::ORDER).unwrap());
        Self(C::Scalar::from(ScalarPrimitive::new(num).unwrap()))
    }
}

impl<C: CurveArithmetic> Point<C> for RustCryptoPoint<C> {
    type Scalar = RustCryptoScalar<C>;

    fn base() -> Self {
        Self(C::ProjectivePoint::generator().to_affine())
    }

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        let pubkey: PublicKey<C> = SecretKey::random(rng).public_key();
        Self(pubkey.as_affine().clone())
    }

    fn add(&self, other: &Self) -> Self {
        let proj = C::ProjectivePoint::from(self.0.clone());
        let other_proj = C::ProjectivePoint::from(other.0.clone());
        Self(proj.add(other_proj).to_affine())
    }

    fn mul(&self, other: &Self::Scalar) -> Self {
        let proj = C::ProjectivePoint::from(self.0.clone());
        Self(proj.mul(other.0).to_affine())
    }
}

impl<C: CurveArithmetic> TryFrom<Box<[u8]>> for RustCryptoPoint<C>
where
    C::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
{
    type Error = SerializationError;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        let encoded_point =
            &EncodedPoint::<C>::from_bytes(value).map_err(|_| SerializationError)?;
        Ok(Self(
            C::AffinePoint::from_encoded_point(encoded_point).unwrap(),
        ))
    }
}

impl<C: CurveArithmetic> Into<Box<[u8]>> for RustCryptoPoint<C>
where
    C::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
{
    fn into(self) -> Box<[u8]> {
        self.0
            .to_encoded_point(false)
            .as_bytes()
            .to_owned()
            .into_boxed_slice()
    }
}

impl<C: CurveArithmetic> TryFrom<Box<[u8]>> for RustCryptoScalar<C>
where
    C::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
{
    type Error = SerializationError;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Ok(Self(
            C::Scalar::from_repr(GenericArray::clone_from_slice(value.as_ref())).unwrap(),
        ))
    }
}

impl<C: CurveArithmetic> Into<Box<[u8]>> for RustCryptoScalar<C>
where
    C::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
{
    fn into(self) -> Box<[u8]> {
        self.0.to_repr().to_vec().into_boxed_slice()
    }
}

#[derive(Clone)]
pub struct PssSecp256k1;

impl PssCompatibleEccCurve for PssSecp256k1 {
    type Curve = Secp256k1;
    type Scalar = RustCryptoScalar<Secp256k1>;
    type Point = RustCryptoPoint<Secp256k1>;
}

#[cfg(test)]
mod tests {
    use crate::ecc::EccGroupManagerPublicKey;
    use crate::rustcryptoecc::PssSecp256k1;
    use crate::{GenericGroupManagerPublicKey, GenericPssSignature, GroupManagerPublicKey};

    #[test]
    fn valid_keys() {
        crate::ecc::tests::valid_keys::<PssSecp256k1>()
    }

    #[test]
    fn valid_signature() {
        crate::ecc::tests::valid_signature::<PssSecp256k1>()
    }

    #[test]
    fn invalid_signature() {
        crate::ecc::tests::invalid_signature::<PssSecp256k1>()
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
