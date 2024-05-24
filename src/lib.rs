use std::collections::HashSet;

use crypto_bigint::{const_residue, impl_modulus, modular::{constant_mod::{Residue, ResidueParams}, Retrieve}, rand_core::OsRng, Encoding, NonZero, RandomMod, U2048};
use sha3::Digest;

const DH_MODP_2048_MODULUS_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
impl_modulus!(DhModp2048Modulus, U2048, DH_MODP_2048_MODULUS_HEX);
const DH_MODP_2048_MODULUS: NonZero<U2048> = NonZero::<U2048>::const_new(U2048::from_be_hex(DH_MODP_2048_MODULUS_HEX)).0;
const DH_MODP_2048_GENERATOR: U2048 = U2048::from_u8(2);
const DH_MODP_2048: Residue<DhModp2048Modulus, { U2048::LIMBS }> = const_residue!(DH_MODP_2048_GENERATOR, DhModp2048Modulus);

pub struct Dpk(Residue<DhModp2048Modulus, { U2048::LIMBS }>);

#[derive(PartialEq, Eq)]
pub struct Dsnym(Residue<DhModp2048Modulus, { U2048::LIMBS }>);

impl core::hash::Hash for Dsnym {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.retrieve().hash(state);
    }
}

#[derive(Debug)]
pub struct PssSignature {
    c: [u8; 32],
    s1: U2048,
    s2: U2048
}

impl PssSignature {
    pub fn new(c: [u8; 32], s1: U2048, s2: U2048) -> Self {
        Self { c, s1, s2 }
    }

    pub fn check_with_list(&self, group: &GroupManagerPublicParameters, dsnym: &Dsnym, dpk: &Dpk, disallow_list:HashSet<Dsnym>, m: &[u8]) -> bool {
        self.check(group, dsnym, dpk, m) && !disallow_list.contains(dsnym)
    }

    pub fn check(&self, group: &GroupManagerPublicParameters, dsnym: &Dsnym, dpk: &Dpk, m: &[u8]) -> bool {
        self.c == self.check_hash(group, dsnym, dpk, m)
    }

    pub fn check_hash(&self, group: &GroupManagerPublicParameters, dsnym: &Dsnym, dpk: &Dpk, m: &[u8]) -> [u8; 32] {
        let c_num = U2048::from_be_slice(&self.c);
        let a1 = group.gpk.pow(&c_num).mul(&DH_MODP_2048.pow(&self.s1)).mul(&group.g2.pow(&self.s2)).retrieve();
        let a2 = dsnym.0.pow(&c_num).mul(&dpk.0.pow(&self.s1)).retrieve();

        let mut c_input: Vec<u8> = Vec::with_capacity(U2048::BYTES * 4 + m.len());
        c_input.extend(dpk.0.retrieve().to_be_bytes());
        c_input.extend(dsnym.0.retrieve().to_be_bytes());
        c_input.extend(a1.to_be_bytes());
        c_input.extend(a2.to_be_bytes());
        c_input.extend(m);
        sha3::Keccak256::digest(&c_input).as_slice().try_into().expect("invalid length")
    }
}

pub struct NymSecretKey {
    x1: U2048,
    x2: U2048
}

impl NymSecretKey {
    pub fn new(x1: U2048, x2: U2048) -> Self {
        Self {
            x1, x2
        }
    }

    pub fn dsnym(&self, dpk: &Dpk) -> Dsnym {
        Dsnym(dpk.0.pow(&self.x1))
    }

    pub fn sig(&self, group: &GroupManagerPublicParameters, dsnym: &Dsnym, dpk: &Dpk, m: &[u8]) -> PssSignature {
        let t1 = U2048::random_mod(&mut OsRng::default(), &DH_MODP_2048_MODULUS);
        let t2 = U2048::random_mod(&mut OsRng::default(), &DH_MODP_2048_MODULUS);
        let a1 = DH_MODP_2048.pow(&t1).mul(&group.g2.pow(&t2)).retrieve();
        let a2 = dpk.0.pow(&t1).retrieve();
        
        let mut c_input: Vec<u8> = Vec::with_capacity(U2048::BYTES * 4 + m.len());
        c_input.extend(dpk.0.retrieve().to_be_bytes());
        c_input.extend(dsnym.0.retrieve().to_be_bytes());
        c_input.extend(a1.to_be_bytes());
        c_input.extend(a2.to_be_bytes());
        c_input.extend(m);
        let c: [u8; 32] = sha3::Keccak256::digest(&c_input).as_slice().try_into().expect("invalid length");

        let t1_residue = Residue::<DhModp2048Modulus, { U2048::LIMBS }>::new(&t1);
        let t2_residue = Residue::new(&t2);
        let x1_residue = Residue::new(&self.x1);
        let x2_residue = Residue::new(&self.x2);
        let c_num = U2048::from_be_slice(&c);
        let c_residue = Residue::new(&c_num);

        let s1 = t1_residue.sub(&c_residue.mul(&x1_residue)).retrieve();
        let s2 = t2_residue.sub(&c_residue.mul(&x2_residue)).retrieve();

        PssSignature::new(c, s1, s2)

    }

    pub fn valid_for_group(&self, group: &GroupManagerPublicParameters) -> bool {
        let y_self = DH_MODP_2048.pow(&self.x1).mul(&group.g2.pow(&self.x2)).retrieve();
        y_self == group.gpk.retrieve()
    }
}

pub struct GroupManagerSecretKey {
    z: U2048,
    x: U2048
}

pub struct GroupManagerPublicParameters {
    g2: Residue<DhModp2048Modulus, { U2048::LIMBS }>,
    gpk: Residue<DhModp2048Modulus, { U2048::LIMBS }>
}

impl GroupManagerSecretKey {
    pub fn new() -> Self {
        let z = U2048::random_mod(&mut OsRng::default(), &DH_MODP_2048_MODULUS);
        let x = U2048::random_mod(&mut OsRng::default(), &DH_MODP_2048_MODULUS);
        Self { z, x }
    }

    pub fn params(&self) -> GroupManagerPublicParameters {
        let g2 = DH_MODP_2048.pow(&self.z);
        let gpk = DH_MODP_2048.pow(&self.x);
        GroupManagerPublicParameters {
            g2, gpk
        }
    }

    pub fn new_dpk(&self) -> Dpk {
        let r = U2048::random_mod(&mut OsRng::default(), &DH_MODP_2048_MODULUS);
        Dpk(DH_MODP_2048.pow(&r))
    }

    pub fn new_gsk(&self) -> NymSecretKey {
        let x_2 = U2048::random_mod(&mut OsRng::default(), &DH_MODP_2048_MODULUS);
        let x_2_residue = Residue::<DhModp2048Modulus, { U2048::LIMBS }>::new(&x_2);
        let z_residue = Residue::new(&self.z);
        let x_residue = Residue::new(&self.x);
        let x_1 = x_residue.sub(&z_residue.mul(&x_2_residue)).retrieve();
        NymSecretKey::new(x_1, x_2)
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let group_manager = GroupManagerSecretKey::new();
        let group_params = group_manager.params();
        let domain = group_manager.new_dpk();
        let user = group_manager.new_gsk();

        println!("Valid key? {}", user.valid_for_group(&group_params));

        let domain_for_user = user.dsnym(&domain);
        let message = "hello test test hello".as_bytes();
        let signature = user.sig(&group_params, &domain_for_user, &domain, message);

        println!("Signature: {:?}", signature);

        let check_hash = signature.check_hash(&group_params, &domain_for_user, &domain, message);

        println!("Check Hash: {:?}", check_hash);

        let valid = signature.check(&group_params, &domain_for_user, &domain, message);

        assert!(valid)
    }
}
