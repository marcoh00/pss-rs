use crate::ecc::{Point, PssCompatibleEccCurve, Scalar, SerializationError};
use rand_core::CryptoRngCore;
use std::ops::{Add, Mul, Sub};
use substrate_bn::{Fq, Fr, Group, G1};

#[derive(Clone, PartialEq)]
pub struct BnPoint(G1);

impl Point<BnCurve> for BnPoint {
    type Scalar = BnScalar;

    fn base() -> Self {
        BnPoint(G1::one())
    }

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        BnPoint(G1::one() * Fr::random(rng))
    }

    fn add(&self, other: &Self) -> Self {
        BnPoint(self.0.add(other.0))
    }

    fn mul(&self, other: &Self::Scalar) -> Self {
        BnPoint(self.0.mul(other.0))
    }
}

impl From<BnPoint> for Box<[u8]> {
    fn from(value: BnPoint) -> Self {
        let mut point = value.0;
        point.normalize();
        assert_eq!(point.z(), Fq::one());
        let mut xy = [0x04; 65];
        point.x().to_big_endian(&mut xy[1..33]).unwrap();
        point.y().to_big_endian(&mut xy[33..]).unwrap();
        xy.into()
    }
}

impl TryFrom<Box<[u8]>> for BnPoint {
    type Error = SerializationError;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        if value.get(0).ok_or(SerializationError)? % 2 != 0x04 {
            return Err(SerializationError);
        }
        let x = Fq::from_slice(&value[1..33]).map_err(|_| SerializationError)?;
        let y = Fq::from_slice(&value[33..]).map_err(|_| SerializationError)?;
        let mut point = G1::zero();
        point.set_x(x);
        point.set_y(y);
        point.set_z(Fq::one());
        Ok(BnPoint(point))
    }
}

#[derive(Clone, PartialEq)]
pub struct BnScalar(Fr);

impl Scalar<BnCurve> for BnScalar {
    type Point = BnPoint;

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        BnScalar(Fr::random(rng))
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
        BnScalar(Fr::from_slice(hash).unwrap())
    }
}

impl From<BnScalar> for Box<[u8]> {
    fn from(value: BnScalar) -> Self {
        let mut be_repr = [0; 32];
        value.0.to_big_endian(&mut be_repr).unwrap();
        be_repr.into()
    }
}

impl TryFrom<Box<[u8]>> for BnScalar {
    type Error = SerializationError;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Fr::from_slice(value.as_ref())
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
    use crate::altbn::PssAltBn128;
    use crate::ecc::{Point, PssCompatibleEccCurve};
    use substrate_bn::Fq;

    #[test]
    fn correct_mod() {
        // p = 21888242871839275222246405745257275088696311157297823662689037894645226208583 = 30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
        let ethereum_mod: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16,
            0xd8, 0x7c, 0xfd, 0x47,
        ];

        let myno = Fq::modulus();
        let mut be = [0u8; 32];
        myno.to_big_endian(&mut be).unwrap();
        assert_eq!(ethereum_mod, be);

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
}
