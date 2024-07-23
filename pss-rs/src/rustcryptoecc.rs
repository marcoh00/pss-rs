use crate::ecc::{Point, Scalar, Serialization, UsableEccCurve};

use crypto_bigint::{generic_array::{sequence::GenericSequence, GenericArray}, ArrayEncoding, NonZero};
use elliptic_curve::{sec1::{EncodedPoint, FromEncodedPoint, ModulusSize}, CurveArithmetic, NonZeroScalar, PublicKey, SecretKey};
use k256::{elliptic_curve::{sec1::ToEncodedPoint, PrimeField, ScalarPrimitive}, Secp256k1};
use rand_core::CryptoRngCore;
use std::ops::{Add, Mul, Rem, Sub};
use group::{Curve as GroupCurve, Group};

pub struct RustCryptoPoint<C: CurveArithmetic>(C::AffinePoint);
pub struct RustCryptoScalar<C: CurveArithmetic>(C::Scalar);

impl<C: CurveArithmetic> Scalar<C> for RustCryptoScalar<C> {
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

    fn from_hash(hash: &[u8]) -> Self {
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
        Self(C::Scalar::from(ScalarPrimitive::new(num).unwrap()))
    }
}

impl<C: CurveArithmetic> Point<C, RustCryptoScalar<C>> for RustCryptoPoint<C> {
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

    fn mul(&self, other: &RustCryptoScalar<C>) -> Self {
        let proj = C::ProjectivePoint::from(self.0.clone());
        Self(proj.mul(other.0).to_affine())
    }
}

impl<C: CurveArithmetic> Serialization for RustCryptoPoint<C>
where C::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>, C::FieldBytesSize: ModulusSize {
    fn serialize(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_owned()
    }

    fn deserialize(buf: &[u8]) -> Self {
        Self(C::AffinePoint::from_encoded_point(&EncodedPoint::<C>::from_bytes(buf).unwrap()).unwrap())
    }
}

impl<C: CurveArithmetic> Serialization for RustCryptoScalar<C> {
    fn serialize(&self) -> Vec<u8> {
        self.0.to_repr().to_vec()
    }

    fn deserialize(buf: &[u8]) -> Self {
        Self(C::Scalar::from_repr(GenericArray::clone_from_slice(buf)).unwrap())
    }
}

struct PssSecp256k1;

impl UsableEccCurve for PssSecp256k1 {
    type Curve = Secp256k1;
    type Point = RustCryptoPoint<Self::Curve>;
    type Scalar = RustCryptoScalar<Self::Curve>;
}
