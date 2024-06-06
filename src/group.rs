use std::marker::PhantomData;

use crypto_bigint::{const_residue, generic_array::GenericArray, impl_modulus, modular::constant_mod::{Residue, ResidueParams}, rand_core::OsRng, ArrayDecoding, CheckedSub, ConcatMixed, Encoding, NonZero, RandomMod, SplitMixed, Uint, U2048, U64};
use sha3::{digest::OutputSizeUser, Digest};

const DH_MODP_2048_MODULUS_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
impl_modulus!(DhModp2048Modulus, U2048, DH_MODP_2048_MODULUS_HEX);
const DH_MODP_2048_GENERATOR: U2048 = U2048::from_u8(2);
pub const DH_MODP_2048: Residue<DhModp2048Modulus, { U2048::LIMBS }> = const_residue!(DH_MODP_2048_GENERATOR, DhModp2048Modulus);

const DH_TINY_TEST_INSECURE_MODULUS_HEX: &str = "000000000000001F";
impl_modulus!(DhTinyTestInsecureModulus, U64, DH_TINY_TEST_INSECURE_MODULUS_HEX);
const DH_TINY_TEST_INSECURE_GENERATOR: U64 = U64::from_u8(3);
pub const DH_TINY_TEST: Residue<DhTinyTestInsecureModulus, { U64::LIMBS }> = const_residue!(DH_TINY_TEST_INSECURE_GENERATOR, DhTinyTestInsecureModulus);

type PkSector<const LIMBS: usize, MOD> = Residue<MOD, LIMBS>;

const ID_DSI: &[u8] = b"TODO replace with algorithm id";

fn signature_hash<const LIMBS: usize, MOD: ResidueParams<LIMBS>, T: AsRef<[u8]>>(q: &Residue<MOD, LIMBS>, a1_i_sector_icc_1: Option<(Residue<MOD, LIMBS>, &Residue<MOD, LIMBS>)>, a2_i_sector_icc_2: Option<(Residue<MOD, LIMBS>, &Residue<MOD, LIMBS>)>, pk_sector: &PkSector<LIMBS, MOD>, message: &[u8]) -> GenericArray<u8, <sha3::Keccak256 as OutputSizeUser>::OutputSize>
where Uint<LIMBS>: Encoding<Repr = T> {
    let mut c_message_buffer = Vec::new();
    c_message_buffer.extend_from_slice(&q.retrieve().to_be_bytes().as_ref());
    if let Some((a1, i_sector_icc_1)) = a1_i_sector_icc_1 {
        c_message_buffer.extend_from_slice(i_sector_icc_1.retrieve().to_be_bytes().as_ref());
        c_message_buffer.extend_from_slice(a1.retrieve().to_be_bytes().as_ref());
    }
    if let Some((a2, i_sector_icc_2)) = a2_i_sector_icc_2 {
        c_message_buffer.extend_from_slice(i_sector_icc_2.retrieve().to_be_bytes().as_ref());
        c_message_buffer.extend_from_slice(a2.retrieve().to_be_bytes().as_ref());
    }
    c_message_buffer.extend_from_slice(pk_sector.retrieve().to_be_bytes().as_ref());
    c_message_buffer.extend_from_slice(ID_DSI);
    c_message_buffer.extend_from_slice(message);


    sha3::Keccak256::digest(&c_message_buffer)
}

#[derive(Debug, Clone)]
pub struct PssSignature<const LIMBS: usize, MOD: ResidueParams<LIMBS>> {
    c: Uint<LIMBS>,
    s1: Uint<LIMBS>,
    s2: Uint<LIMBS>,
    pseudonyms: (Option<Residue<MOD, LIMBS>>, Option<Residue<MOD, LIMBS>>)
}

#[derive(Debug)]
pub struct PssSigner<'a, const LIMBS: usize, MOD: ResidueParams<LIMBS>>
where Uint<LIMBS>: Encoding {
    g: &'a Residue<MOD, LIMBS>,
    sk_icc_1_u: &'a Uint<LIMBS>,
    sk_icc_2_u: &'a Uint<LIMBS>,
    pk_sector: &'a Residue<MOD, LIMBS>,
    pk_m: &'a Residue<MOD, LIMBS>,
    i_sector_icc_1: Option<Residue<MOD, LIMBS>>,
    i_sector_icc_2: Option<Residue<MOD, LIMBS>>,
}

impl<'a, const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>> PssSigner<'a, LIMBS, MOD>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    pub fn sign(&self, message: &[u8]) -> PssSignature<LIMBS, MOD> {
        let k1 = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        let k2 = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));

        // println!("k1 = {}, k2 = {}", k1, k2);

        let g_k1 = self.g.pow(&k1);
        let pk_m_k2 = self.pk_m.pow(&k2);
        let q = g_k1.mul(&pk_m_k2);

        // println!("Q = g^k1 * PK_m^k2 = {}^{} * {}^{} = {} * {} = {}", self.g.retrieve(), k1, self.pk_m.retrieve(), k2, g_k1.retrieve(), pk_m_k2.retrieve(), q.retrieve());

        let pseudonym1 = match self.i_sector_icc_1 {
            Some(ref pubkey) => Some((self.pk_sector.pow(&k1), pubkey)),
            None => None
        };
        let pseudonym2 = match self.i_sector_icc_2 {
            Some(ref pubkey) => Some((self.pk_sector.pow(&k2), pubkey)),
            None => None
        };

        // println!("A1 = PK_sector ^ k1 | PK_sector ^ SK_icc_1 = {:?}", pseudonym1.map(|(pkpow, pubkey)| (pkpow.retrieve(), pubkey.retrieve())));
        // println!("A2 = PK_sector ^ k2 | PK_sector ^ SK_icc_2 = {:?}", pseudonym2.map(|(pkpow, pubkey)| (pkpow.retrieve(), pubkey.retrieve())));

        let c_bin = signature_hash(&q, pseudonym1, pseudonym2, &self.pk_sector, message);
        let c = c_bin.into_uint_be().resize();

        // println!("c = {} = {}", &c_bin.iter().map(|b| format!("{:X}", b)).collect::<String>(), c);

        let fermat_modulus = MOD::MODULUS.checked_sub(&Uint::from_u8(1)).unwrap();

        let c_sk_icc_1_u = mul_mod(self.sk_icc_1_u, &c, &fermat_modulus);
        let c_sk_icc_2_u = mul_mod(self.sk_icc_2_u, &c, &fermat_modulus);

        let s1 = k1.sub_mod(&c_sk_icc_1_u, &fermat_modulus);
        let s2 = k2.sub_mod(&c_sk_icc_2_u, &fermat_modulus);

        // println!("s1 = k1 - c * SK_icc_1 = {} - {} * {} = {} - {} = {}", k1, c, self.sk_icc_1_u, k1, c_sk_icc_1_u, s1);
        // println!("s2 = k2 - c * SK_icc_2 = {} - {} * {} = {} - {} = {}", k2, c, self.sk_icc_2_u, k2, c_sk_icc_2_u, s2);

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

pub struct SectorSpecificIdentifiers<const LIMBS: usize, MOD: ResidueParams<LIMBS>> {
    i_sector_icc_1: Residue<MOD, LIMBS>,
    i_sector_icc_2: Residue<MOD, LIMBS>
}

impl<const LIMBS: usize, MOD: ResidueParams<LIMBS>> SectorSpecificIdentifiers<LIMBS, MOD> {
    pub fn new(i_sector_icc_1: Residue<MOD, LIMBS>, i_sector_icc_2: Residue<MOD, LIMBS>) -> Self {
        Self { i_sector_icc_1, i_sector_icc_2 }
    }
}

#[derive(Debug)]
pub struct Icc<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    gpk: GroupManagerPublicKey<LIMBS, MOD>,
    sk_icc_1_u: Uint<LIMBS>,
    sk_icc_2_u: Uint<LIMBS>,
    _mod: PhantomData<MOD>
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>> Icc<LIMBS, WIDE_LIMBS, MOD>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    pub fn new(gpk: GroupManagerPublicKey<LIMBS, MOD>, sk_icc_1_u: Uint<LIMBS>, sk_icc_2_u: Uint<LIMBS>) -> Self {
        Self {
            gpk, sk_icc_1_u, sk_icc_2_u, _mod: PhantomData
        }
    }

    pub fn sector_identifiers(&self, pk_sector: &PkSector<LIMBS, MOD>) -> SectorSpecificIdentifiers<LIMBS, MOD> {
        let i_sector_icc_1 = pk_sector.pow(&self.sk_icc_1_u);
        let i_sector_icc_2 = pk_sector.pow(&self.sk_icc_2_u);
        SectorSpecificIdentifiers::new(i_sector_icc_1, i_sector_icc_2)
    }

    pub fn signer<'pk, 'me: 'pk>(&'me self, pk_sector: &'pk PkSector<LIMBS, MOD>, use_identifier1: bool, use_identifier2: bool) -> PssSigner<'pk, LIMBS, MOD> {
        let identifiers = self.sector_identifiers(pk_sector);
        let (i_sector_icc_1, i_sector_icc_2) = match (use_identifier1, use_identifier2) {
            (true, true) => (Some(identifiers.i_sector_icc_1), Some(identifiers.i_sector_icc_2)),
            (true, false) => (Some(identifiers.i_sector_icc_1), None),
            (false, true) => (None, Some(identifiers.i_sector_icc_2)),
            (false, false) => (None, None)
        };
        PssSigner {
            g: &self.gpk.g,
            sk_icc_1_u: &self.sk_icc_1_u,
            sk_icc_2_u: &self.sk_icc_2_u,
            pk_sector: pk_sector,
            pk_m: &self.gpk.pk_m,
            i_sector_icc_1,
            i_sector_icc_2
        }
    }

    pub fn valid_for_gpk(&self, group: &GroupManagerPublicKey<LIMBS, MOD>) -> bool {
        // g^sk_icc_1_u * pk_m^sk_icc_2_u == pk_icc
        let part1 = group.g.pow(&self.sk_icc_1_u);
        let part2 = group.pk_m.pow(&self.sk_icc_2_u);
        let y_self = part1.mul(&part2).retrieve();
        // println!("g1 = {:?}, g2 = {:?}, g1^x1 = {:?}, g2^x2 = {:?}, g1^x1*g2^x2 = {:?}", group.g.retrieve(), group.pk_icc.retrieve(), part1.retrieve(), part2.retrieve(), y_self);
        y_self == group.pk_icc.retrieve()
    }
}

#[derive(Clone, Debug)]
pub struct GroupManagerPublicKey<const LIMBS: usize, MOD: ResidueParams<LIMBS>> {
    g: Residue<MOD, LIMBS>,
    pk_icc: Residue<MOD, LIMBS>,
    pk_m: Residue<MOD, LIMBS>
}

impl<const LIMBS: usize, MOD: ResidueParams<LIMBS>> GroupManagerPublicKey<LIMBS, MOD>
where Uint<LIMBS>: Encoding {
    pub fn new(g: Residue<MOD, LIMBS>, pk_icc: Residue<MOD, LIMBS>, pk_m: Residue<MOD, LIMBS>) -> Self {
        Self { g, pk_icc, pk_m }
    }

    pub fn check_signature(&self, message: &[u8], pk_sector: &PkSector<LIMBS, MOD>, signature: &PssSignature<LIMBS, MOD>) -> bool {
        self.recover_c(message, pk_sector, signature) == signature.c
    }

    pub(crate) fn recover_c(&self, message: &[u8], pk_sector: &PkSector<LIMBS, MOD>, signature: &PssSignature<LIMBS, MOD>) -> Uint<LIMBS> {
        let pk_icc_c = self.pk_icc.pow(&signature.c);
        let g_s1 = self.g.pow(&signature.s1);
        let pk_m_s2 = self.pk_m.pow(&signature.s2);
        let q = pk_icc_c.mul(&g_s1).mul(&pk_m_s2);

        // println!("Q' = PK_icc^c * g^s1 * PK_m^s2 = {} * {} * {} = {}", pk_icc_c.retrieve(), g_s1.retrieve(), pk_m_s2.retrieve(), q.retrieve());

        let pseudonym1 = match signature.pseudonyms.0 {
            Some(ref pubkey) => {
                let sector_c = pubkey.pow(&signature.c);
                let pk_s = pk_sector.pow(&signature.s1);
                let a1 = sector_c.mul(&pk_s);
                // println!("A1' = I_icc_1^c * PK_sector^s1 = {}^{} * {}^{} = {} * {} = {}", pubkey.retrieve(), signature.c, pk_sector.retrieve(), signature.s1, sector_c.retrieve(), pk_s.retrieve(), a1.retrieve());
                Some((a1, pubkey))
            },
            None => None,
        };
        let pseudonym2 = match signature.pseudonyms.1 {
            Some(ref pubkey) => {
                let sector_c = pubkey.pow(&signature.c);
                let pk_s = pk_sector.pow(&signature.s2);
                let a2 = sector_c.mul(&pk_s);
                // println!("A2' = I_icc_2^c * PK_sector^s2 = {}^{} * {}^{} = {} * {} = {}", pubkey.retrieve(), signature.c, pk_sector.retrieve(), signature.s2, sector_c.retrieve(), pk_s.retrieve(), a2.retrieve());
                Some((a2, pubkey))
            },
            None => None,
        };

        let c_bytes = signature_hash(&q, pseudonym1, pseudonym2, pk_sector, message);
        let c = c_bytes.into_uint_be().resize();

        // println!("c = {} = {}", &c_bytes.iter().map(|b| format!("{:X}", b)).collect::<String>(), c);

        c
    }
}

#[derive(Debug)]
pub struct GroupManager<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    sk_m: Uint<LIMBS>,
    sk_icc: Uint<LIMBS>,
    gpk: GroupManagerPublicKey<LIMBS, MOD>,
    sectors: Vec<(PkSector<LIMBS, MOD>, Option<Uint<LIMBS>>)>,
    _mod: PhantomData<MOD>
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>> GroupManager<LIMBS, WIDE_LIMBS, MOD>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    pub fn new(g: Residue<MOD, LIMBS>) -> Self {
        let sk_m = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        let sk_icc = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        let pk_m = g.pow(&sk_m);
        let pk_icc = g.pow(&sk_icc);
        // println!("g = {}, SK_m = {}, SK_icc = {}", g.retrieve(), sk_m, sk_icc);
        // println!("PK_m = g^SK_m = {}^{} = {}", g.retrieve(), sk_m, pk_m.retrieve());
        // println!("PK_icc = g^SK_icc = {}^{} = {}", g.retrieve(), sk_icc, pk_icc.retrieve());
        let gpk = GroupManagerPublicKey::new(g, pk_icc, pk_m);
        Self { sk_m, sk_icc, gpk, sectors: Vec::new(), _mod: PhantomData }
    }

    pub fn renew_icc(&mut self) -> Uint<LIMBS> {
        let mut sk_icc = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        self.gpk.pk_icc = self.gpk.g.pow(&sk_icc);
        std::mem::swap(&mut self.sk_icc, &mut sk_icc);
        sk_icc
    }

    pub fn public_key(&self) -> &GroupManagerPublicKey<LIMBS, MOD> {
        &self.gpk
    }

    pub fn new_sector(&mut self, deanonymizable: bool) -> PkSector<LIMBS, MOD> {
        let sk_sector = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        let pk_sector = self.gpk.g.pow(&sk_sector);

        // println!("SK_sector = {}", sk_sector);
        // println!("PK_sector = g^SK_sector = {}^{} = {}", self.gpk.g.retrieve(), sk_sector, pk_sector.retrieve());

        self.sectors.push((pk_sector.clone(), match deanonymizable {
            true => Some(sk_sector),
            false => None
        }));
        pk_sector
    }

    pub fn new_icc(&self) -> Icc<LIMBS, WIDE_LIMBS, MOD> {
        let sk_icc_2_u = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        // SK_ICC_1 = SK_ICC - SK_M * SK_ICC_2
        let fermat_modulus = MOD::MODULUS.checked_sub(&Uint::from_u8(1)).unwrap();
        let multiplication = mul_mod(&self.sk_m, &sk_icc_2_u, &fermat_modulus);
        let sk_icc_1_u = self.sk_icc.sub_mod(&multiplication, &fermat_modulus);

        // println!("SK_icc_2 = {}, fermat_modulus = {}", sk_icc_2_u, fermat_modulus);
        // println!("SK_icc_1 = SK_icc - SK_m * SK_icc_2 = {} - {} * {} = {} - {} = {}", self.sk_icc, self.sk_m, sk_icc_2_u, self.sk_icc, multiplication, sk_icc_1_u);
        Icc::new(self.gpk.clone(), sk_icc_1_u, sk_icc_2_u)
    }

}

fn mul_mod<const LIMBS: usize, const WIDE_LIMBS: usize>(a: &Uint<LIMBS>, b: &Uint<LIMBS>, p: &Uint<LIMBS>) -> Uint<LIMBS>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    let mul = a.mul(&b);
    let wide_modulus = Uint::<LIMBS>::from_u8(0).concat_mixed(p);
    let residue = mul.rem(&NonZero::from_uint(wide_modulus));
    residue.resize()
}


#[cfg(test)]
mod tests {
    use super::*;

    const SIGN_MESSAGE: &[u8] = b"TEST MESSAGE";

    #[test]
    fn it_works() {
        let mut group_manager = GroupManager::new(DH_MODP_2048);
        let icc = group_manager.new_icc();
        let sector = group_manager.new_sector(false);
        let signer = icc.signer(&sector, true, true);
        let signature = signer.sign(SIGN_MESSAGE);
        let valid = group_manager.public_key().check_signature(SIGN_MESSAGE, &sector, &signature);

        assert!(valid)
    }

    #[test]
    fn valid_keys() {
        let mut group_manager = GroupManager::new(DH_MODP_2048);
        let nym = group_manager.new_icc();
        assert!(nym.valid_for_gpk(group_manager.public_key()));

        let _ = group_manager.renew_icc();
        assert!(!nym.valid_for_gpk(group_manager.public_key()));
    }
}
