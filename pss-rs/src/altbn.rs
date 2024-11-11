use crate::ecc::{Point, PssCompatibleEccCurve, Scalar, SerializationError};
use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand_core::CryptoRngCore;
use std::ops::{Add, Mul, Sub};

#[derive(Clone, PartialEq)]
pub struct BnPoint(G1);

impl Point<BnCurve> for BnPoint {
    type Scalar = BnScalar;

    fn base() -> Self {
        let generator = G1::generator();
        BnPoint(generator)
    }

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        let rand = G1::rand(rng);
        BnPoint(rand)
    }

    fn add(&self, other: &Self) -> Self {
        let added = self.0.add(other.0);
        BnPoint(added)
    }

    fn mul(&self, other: &Self::Scalar) -> Self {
        let multiplied = self.0.mul(other.0);
        BnPoint(multiplied)
    }
}

impl From<BnPoint> for Box<[u8]> {
    fn from(value: BnPoint) -> Self {
        //let mut point = value.0.;
        //point.normalize()
        //assert_eq!(point.z(), Fq::one());
        let affine = value.0.into_affine();
        let mut x_le = [0; 33];
        let mut y_le = [0; 33];

        let ptr: &mut [u8] = &mut x_le;
        affine.x().unwrap().serialize_uncompressed(ptr).unwrap();

        let ptr: &mut [u8] = &mut y_le;
        affine.y().unwrap().serialize_uncompressed(ptr).unwrap();

        x_le.reverse();
        y_le.reverse();

        let mut xy = [0x04; 65];
        xy[1..33].copy_from_slice(&x_le[1..33]);
        xy[33..65].copy_from_slice(&y_le[1..33]);
        xy.into()
    }
}

impl TryFrom<Box<[u8]>> for BnPoint {
    type Error = SerializationError;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        let mut le_repr: [u8; 65] = [0x04; 65];
        // value is 4, [x], [y] in BE
        let rev: Vec<u8> = value.iter().rev().cloned().collect();
        // rev is [y], [x], 4 in LE
        le_repr[0..32].copy_from_slice(&rev[32..64]);
        le_repr[32..64].copy_from_slice(&rev[0..32]);
        let point =
            G1::deserialize_uncompressed(le_repr.as_slice()).map_err(|_| SerializationError)?;
        Ok(BnPoint(point))
    }
}

#[derive(Clone, PartialEq)]
pub struct BnScalar(Fr);

impl Scalar<BnCurve> for BnScalar {
    type Point = BnPoint;

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        BnScalar(Fr::rand(rng))
    }

    fn add(&self, other: &Self) -> Self {
        BnScalar(self.0.add(other.0))
    }

    fn sub(&self, other: &Self) -> Self {
        BnScalar(self.0.sub(other.0))
    }

    fn mul(&self, other: &Self) -> Self {
        BnScalar(self.0.mul(other.0))
    }

    fn to_point(&self) -> Self::Point {
        Self::Point::base().mul(self)
    }

    fn from_hash(hash: &[u8]) -> Self {
        let mut temp: [u8; 32] = [0; 32];
        temp.copy_from_slice(hash);
        temp[0] &= 0x1F;
        let b: Box<[u8]> = Box::from(temp);
        Self::try_from(b).unwrap()
    }
}

impl From<BnScalar> for Box<[u8]> {
    fn from(value: BnScalar) -> Self {
        let mut le_repr = [0; 32];
        let ptr: &mut [u8] = &mut le_repr;
        value.0.serialize_uncompressed(ptr).unwrap();
        le_repr.into_iter().rev().collect()
    }
}

impl TryFrom<Box<[u8]>> for BnScalar {
    type Error = SerializationError;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        let le_repr: Vec<u8> = value.iter().cloned().rev().collect();
        Fr::deserialize_uncompressed(le_repr.as_slice())
            .map(|fr| BnScalar(fr))
            .map_err(|_| SerializationError)
    }
}

pub struct BnCurve;

#[derive(Clone)]
pub struct PssAltBn128;

impl PssCompatibleEccCurve for PssAltBn128 {
    const ID_DSI: &'static [u8] = b"ECC-ALTBN128-G1";
    type Curve = BnCurve;
    type Scalar = BnScalar;
    type Point = BnPoint;
}

#[cfg(test)]
mod tests {
    use crate::altbn::{BnPoint, BnScalar, PssAltBn128};
    use crate::ecc::{Point, PssCompatibleEccCurve, Scalar};
    use ark_bn254::Fq;
    use ark_ff::{BigInteger, PrimeField};
    use rand_core::OsRng;

    #[test]
    fn correct_mod() {
        // p = 21888242871839275222246405745257275088696311157297823662689037894645226208583 = 30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
        let ethereum_mod: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16,
            0xd8, 0x7c, 0xfd, 0x47,
        ];

        let myno = Fq::MODULUS;
        assert_eq!(&ethereum_mod, myno.to_bytes_be().as_slice());

        let base = <PssAltBn128 as PssCompatibleEccCurve>::Point::base();
        let serialized: Box<[u8]> = base.into();

        let expected: &[u8] = &[
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 2,
        ];
        assert_eq!(serialized.as_ref(), expected);
    }

    #[test]
    fn point_serializaion() {
        let point = BnPoint::random(&mut OsRng::default());
        let serialized: Box<[u8]> = point.clone().into();
        let deserialized: BnPoint = serialized.clone().try_into().unwrap();
        let serialized2: Box<[u8]> = deserialized.clone().into();
        assert_eq!(serialized, serialized2);
        assert!(point == deserialized);
    }

    #[test]
    fn scalar_serialization() {
        let data: Box<[u8]> = [
            31, 240, 209, 167, 145, 75, 72, 11, 160, 147, 173, 65, 129, 188, 8, 172, 85, 21, 79,
            53, 243, 215, 48, 82, 102, 245, 127, 232, 103, 230, 37, 92,
        ]
        .into();
        let deserialized1: BnScalar = data.clone().try_into().unwrap();
        let serialized2: Box<[u8]> = deserialized1.clone().into();
        let deserialized2: BnScalar = serialized2.clone().try_into().unwrap();
        assert_eq!(data, serialized2);
        assert!(deserialized1 == deserialized2);
    }

    #[test]
    fn random_scalar_serialization() {
        let scalar = BnScalar::random(&mut OsRng::default());
        let serialized: Box<[u8]> = scalar.into();
        let deserialized: BnScalar = serialized.clone().try_into().unwrap();
        let serialized2: Box<[u8]> = deserialized.into();
        assert_eq!(serialized, serialized2);
    }

    #[test]
    fn valid_keys() {
        crate::ecc::tests::valid_keys::<PssAltBn128>()
    }

    #[test]
    fn valid_signature() {
        crate::ecc::tests::valid_signature::<PssAltBn128>()
    }

    #[test]
    fn invalid_signature() {
        crate::ecc::tests::invalid_signature::<PssAltBn128>()
    }

    #[test]
    fn mult_test() {
        let point_data: Box<[u8]> = [
            4, 42, 16, 119, 23, 202, 55, 238, 55, 194, 39, 0, 96, 18, 84, 163, 131, 167, 4, 150,
            45, 211, 54, 209, 214, 246, 81, 3, 212, 82, 145, 38, 188, 32, 201, 132, 249, 173, 194,
            221, 166, 34, 177, 193, 177, 28, 60, 50, 196, 117, 18, 82, 73, 167, 50, 176, 197, 34,
            46, 221, 244, 225, 75, 250, 222,
        ]
        .into();
        let point = BnPoint::try_from(point_data).unwrap();

        let scalar_data: Box<[u8]> = [
            46, 41, 34, 94, 63, 162, 37, 182, 201, 88, 162, 52, 254, 98, 23, 2, 113, 83, 124, 100,
            119, 252, 156, 173, 62, 3, 230, 179, 125, 202, 234, 100,
        ]
        .into();
        let scalar = BnScalar::try_from(scalar_data).unwrap();

        let result = point.mul(&scalar);
        let serialized: Box<[u8]> = result.clone().into();

        let expected: Box<[u8]> = [
            4, 2, 169, 249, 31, 171, 213, 31, 221, 254, 252, 195, 53, 27, 44, 219, 154, 214, 32,
            62, 198, 140, 33, 115, 235, 174, 219, 59, 250, 133, 150, 172, 186, 34, 60, 155, 243,
            85, 80, 173, 109, 41, 97, 86, 1, 145, 30, 8, 26, 121, 200, 253, 60, 83, 187, 47, 50,
            109, 120, 120, 139, 151, 39, 166, 184,
        ]
        .into();
        assert_eq!(serialized, expected);
    }
}
