use std::{collections::HashSet, marker::PhantomData};

use crypto_bigint::{const_residue, impl_modulus, modular::{constant_mod::{Residue, ResidueParams}, Retrieve}, rand_core::OsRng, CheckedSub, ConcatMixed, Encoding, NonZero, RandomMod, SplitMixed, Uint, U2048, U64};
use sha3::Digest;

const DH_MODP_2048_MODULUS_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
impl_modulus!(DhModp2048Modulus, U2048, DH_MODP_2048_MODULUS_HEX);
const DH_MODP_2048_GENERATOR: U2048 = U2048::from_u8(2);
pub const DH_MODP_2048: Residue<DhModp2048Modulus, { U2048::LIMBS }> = const_residue!(DH_MODP_2048_GENERATOR, DhModp2048Modulus);

const DH_TINY_TEST_INSECURE_MODULUS_HEX: &str = "000000000000001F";
impl_modulus!(DhTinyTestInsecureModulus, U64, DH_TINY_TEST_INSECURE_MODULUS_HEX);
const DH_TINY_TEST_INSECURE_GENERATOR: U64 = U64::from_u8(3);
pub const DH_TINY_TEST: Residue<DhTinyTestInsecureModulus, { U64::LIMBS }> = const_residue!(DH_TINY_TEST_INSECURE_GENERATOR, DhTinyTestInsecureModulus);

type PkSector<const LIMBS: usize, MOD> = Residue<MOD, LIMBS>;

#[derive(PartialEq, Eq, Debug)]
pub struct Dsnym<const LIMBS: usize, MOD: ResidueParams<LIMBS>>(Residue<MOD, LIMBS>);

impl<const LIMBS: usize, MOD: ResidueParams<LIMBS>> core::hash::Hash for Dsnym<LIMBS, MOD> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.retrieve().hash(state);
    }
}

#[derive(Debug)]
pub struct PssSignature<const LIMBS: usize, MOD: ResidueParams<LIMBS>>
where Uint<LIMBS>: Encoding {
    c: [u8; 32],
    s1: Uint<LIMBS>,
    s2: Uint<LIMBS>,
    _mod: PhantomData<MOD>
}

impl<const LIMBS: usize, MOD: ResidueParams<LIMBS>> PssSignature<LIMBS, MOD>
where Uint<LIMBS>: Encoding {
    pub fn new(c: [u8; 32], s1: Uint<LIMBS>, s2: Uint<LIMBS>) -> Self {
        Self { c, s1, s2, _mod: PhantomData }
    }

    pub fn check_with_list(&self, group: &GroupManagerPublicKey<LIMBS, MOD>, dsnym: &Dsnym<LIMBS, MOD>, pk_sector: &PkSector<LIMBS, MOD>, disallow_list:HashSet<Dsnym<LIMBS, MOD>>, m: &[u8]) -> bool {
        self.check(group, dsnym, pk_sector, m) && !disallow_list.contains(dsnym)
    }

    pub fn check(&self, group: &GroupManagerPublicKey<LIMBS, MOD>, dsnym: &Dsnym<LIMBS, MOD>, pk_sector: &PkSector<LIMBS, MOD>, m: &[u8]) -> bool {
        self.c == self.check_hash(group, dsnym, pk_sector, m)
    }

    pub fn check_hash(&self, group: &GroupManagerPublicKey<LIMBS, MOD>, dsnym: &Dsnym<LIMBS, MOD>, pk_sector: &PkSector<LIMBS, MOD>, m: &[u8]) -> [u8; 32] {
        let mut c_num_bytes = Vec::with_capacity(Uint::<LIMBS>::BYTES);
        for i in 0..Uint::<LIMBS>::BYTES {
            if i < 32 {
                c_num_bytes.push(self.c[i]);
            } else {
                c_num_bytes.push(0);
            }
        }
        let c_num = Uint::<LIMBS>::from_be_slice(&c_num_bytes);
        let a1 = group.pk_m.pow(&c_num).mul(&group.g.pow(&self.s1)).mul(&group.pk_icc.pow(&self.s2)).retrieve();
        let a2 = dsnym.0.pow(&c_num).mul(&pk_sector.pow(&self.s1)).retrieve();

        let mut c_input: Vec<u8> = Vec::with_capacity(U2048::BYTES * 4 + m.len());
        c_input.extend(pk_sector.retrieve().to_be_bytes().as_ref());
        c_input.extend(dsnym.0.retrieve().to_be_bytes().as_ref());
        c_input.extend(a1.to_be_bytes().as_ref());
        c_input.extend(a2.to_be_bytes().as_ref());
        c_input.extend(m);
        sha3::Keccak256::digest(&c_input).as_slice().try_into().expect("invalid length")
    }
}

#[derive(Debug)]
pub struct Icc<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    sk_icc_1_u: Uint<LIMBS>,
    sk_icc_2_u: Uint<LIMBS>,
    _mod: PhantomData<MOD>
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>> Icc<LIMBS, WIDE_LIMBS, MOD>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    pub fn new(sk_icc_1_u: Uint<LIMBS>, sk_icc_2_u: Uint<LIMBS>) -> Self {
        Self {
            sk_icc_1_u, sk_icc_2_u, _mod: PhantomData
        }
    }

    pub fn dsnym(&self, pk_sector: &PkSector<LIMBS, MOD>) -> Dsnym<LIMBS, MOD> {
        Dsnym(pk_sector.pow(&self.sk_icc_1_u))
    }

    pub fn sig(&self, group: &GroupManagerPublicKey<LIMBS, MOD>, dsnym: &Dsnym<LIMBS, MOD>, pk_sector: &PkSector<LIMBS, MOD>, m: &[u8]) -> PssSignature<LIMBS, MOD> {
        let t1 = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        let t2 = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        let a1 = group.g.pow(&t1).mul(&group.pk_icc.pow(&t2)).retrieve();
        let a2 = pk_sector.pow(&t1).retrieve();

        println!("t1={:?}, t2={:?}, a1=g1^t1*g2^t2={:?}, pk_sector={:?}, a2=pk_sector^t1={:?}", t1, t2, a1, pk_sector.retrieve(), a2);
        
        let mut c_input: Vec<u8> = Vec::with_capacity(U2048::BYTES * 4 + m.len());
        c_input.extend(pk_sector.retrieve().to_be_bytes().as_ref());
        c_input.extend(dsnym.0.retrieve().to_be_bytes().as_ref());
        c_input.extend(a1.to_be_bytes().as_ref());
        c_input.extend(a2.to_be_bytes().as_ref());
        c_input.extend(m);
        let c: [u8; 32] = sha3::Keccak256::digest(&c_input).as_slice().try_into().expect("invalid length");

        let mut c_num_bytes = Vec::with_capacity(Uint::<LIMBS>::BYTES);
        for i in 0..Uint::<LIMBS>::BYTES {
            if i < 32 {
                c_num_bytes.push(c[i]);
            } else {
                c_num_bytes.push(0);
            }
        }
        let c_num = Uint::<LIMBS>::from_be_slice(&c_num_bytes);
        let c_residue = Residue::<MOD, LIMBS>::new(&c_num);

        println!("c_num={:?}, c_residue={:?}", c_num, c_residue.retrieve());

        let fermat_modulus = MOD::MODULUS.checked_sub(&Uint::from_u8(1)).unwrap();
        let c_x1 = mul_mod(&c_num, &self.sk_icc_1_u, &fermat_modulus);
        let s1 = t1.sub_mod(&c_x1, &fermat_modulus);

        let fermat_modulus = MOD::MODULUS.checked_sub(&Uint::from_u8(1)).unwrap();
        let c_x2 = mul_mod(&c_num, &self.sk_icc_2_u, &fermat_modulus);
        let s2 = t2.sub_mod(&c_x2, &fermat_modulus);

        println!("s1=t1-c*x1={:?}, s2=t2-c*x2={:?}", s1, s2);

        PssSignature::new(c, s1, s2)

    }

    pub fn valid_for_group(&self, group: &GroupManagerPublicKey<LIMBS, MOD>) -> bool {
        let part1 = group.g.pow(&self.sk_icc_1_u);
        let part2 = group.pk_icc.pow(&self.sk_icc_2_u);
        let y_self = part1.mul(&part2).retrieve();
        println!("g1 = {:?}, g2 = {:?}, g1^x1 = {:?}, g2^x2 = {:?}, g1^x1*g2^x2 = {:?}", group.g.retrieve(), group.pk_icc.retrieve(), part1.retrieve(), part2.retrieve(), y_self);
        y_self == group.pk_m.retrieve()
    }
}

#[derive(Debug)]
pub struct GroupManager<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    sk_m: Uint<LIMBS>,
    sk_icc: Uint<LIMBS>,
    g: Residue<MOD, LIMBS>,
    _mod: PhantomData<MOD>
}

#[derive(Debug)]
pub struct GroupManagerPublicKey<const LIMBS: usize, MOD: ResidueParams<LIMBS>> {
    g: Residue<MOD, LIMBS>,
    pk_icc: Residue<MOD, LIMBS>,
    pk_m: Residue<MOD, LIMBS>
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>> GroupManager<LIMBS, WIDE_LIMBS, MOD>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    pub fn new(g: Residue<MOD, LIMBS>) -> Self {
        let z = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        let x = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        Self { sk_m: z, sk_icc: x, g, _mod: PhantomData }
    }

    pub fn params(&self) -> GroupManagerPublicKey<LIMBS, MOD> {
        let g2 = self.g.pow(&self.sk_m);
        let gpk = self.g.pow(&self.sk_icc);
        println!("z={:?}, x={:?}, g={:?}, gpk/g^x={:?}", self.sk_m, self.sk_icc, self.g.retrieve(), gpk.retrieve());
        GroupManagerPublicKey {
            g: self.g.clone(), pk_icc: g2, pk_m: gpk
        }
    }

    pub fn new_sector(&self, deanonymizable: bool) -> PkSector<LIMBS, MOD> {
        let r = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        self.g.pow(&r)
    }

    pub fn new_icc(&self) -> Icc<LIMBS, WIDE_LIMBS, MOD> {
        let sk_icc_2_u = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        // SK_ICC_1 = SK_ICC - SK_M * SK_ICC_2
        let fermat_modulus = MOD::MODULUS.checked_sub(&Uint::from_u8(1)).unwrap();
        let multiplication = mul_mod(&self.sk_m, &sk_icc_2_u, &fermat_modulus);
        let sk_icc_1_u = self.sk_icc.sub_mod(&multiplication, &fermat_modulus);
        println!("x2 = {}, mod-1 = {}, z*x2 = {}, x-z*x2 = {}", sk_icc_2_u, fermat_modulus, multiplication, sk_icc_1_u);
        Icc::new(sk_icc_1_u, sk_icc_2_u)
    }

}

fn mul_mod<const LIMBS: usize, const WIDE_LIMBS: usize>(a: &Uint<LIMBS>, b: &Uint<LIMBS>, p: &Uint<LIMBS>) -> Uint<LIMBS>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    let mul = a.mul(&b);
    let wide_modulus = Uint::<LIMBS>::from_u8(0).concat_mixed(p);
    let residue = mul.div_rem(&NonZero::from_uint(wide_modulus)).1;
    residue.split_mixed().1
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let group_manager = GroupManager::new(DH_TINY_TEST);
        let group_params = group_manager.params();
        let domain = group_manager.new_sector(true);
        let user = group_manager.new_icc();

        println!("Group Manager: {:?}", group_manager);
        println!("Group Params: {:?}", group_params);
        println!("Domain: {:?}", domain);
        println!("User: {:?}", user);

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
