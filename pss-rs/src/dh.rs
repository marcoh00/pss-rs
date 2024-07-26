use std::{marker::PhantomData, ops::Deref};

pub use crypto_bigint::{Uint, modular::constant_mod::ResidueParams, ConcatMixed};

use crypto_bigint::{const_residue, generic_array::GenericArray, impl_modulus, modular::constant_mod::Residue, rand_core::OsRng, ArrayDecoding, CheckedSub, Encoding, NonZero, RandomMod, SplitMixed, U2048, U64};
use sha3::{digest::OutputSizeUser, Digest};

use crate::{mul_mod, GenericGroupManagerPrivateKey, GenericGroupManagerPublicKey, GenericIccSecretKey, GenericPssSignature, GenericPublicKey, GroupManager, GroupManagerPublicKey, Icc, PssSignature, PssSigner};

const DH_MODP_2048_MODULUS_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
impl_modulus!(DhModp2048Modulus, U2048, DH_MODP_2048_MODULUS_HEX);
const DH_MODP_2048_GENERATOR: U2048 = U2048::from_u8(2);
pub const DH_MODP_2048_RESIDUE: Residue<DhModp2048Modulus, { U2048::LIMBS }> = const_residue!(DH_MODP_2048_GENERATOR, DhModp2048Modulus);
pub const DH_MODP_2048: PssDhPublicKey<DhModp2048Modulus, { U2048::LIMBS }> = PssDhPublicKey(DH_MODP_2048_RESIDUE);

const DH_TINY_TEST_INSECURE_MODULUS_HEX: &str = "000000000000001F";
impl_modulus!(DhTinyTestInsecureModulus, U64, DH_TINY_TEST_INSECURE_MODULUS_HEX);
const DH_TINY_TEST_INSECURE_GENERATOR: U64 = U64::from_u8(3);
pub const DH_TINY_TEST: Residue<DhTinyTestInsecureModulus, { U64::LIMBS }> = const_residue!(DH_TINY_TEST_INSECURE_GENERATOR, DhTinyTestInsecureModulus);

const ID_DSI: &[u8] = b"TODO replace with algorithm id";

#[derive(Clone, Debug)]
pub struct PssDhPublicKey<MOD: ResidueParams<LIMBS>, const LIMBS: usize> (Residue<MOD, LIMBS>);

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> From<Residue<MOD, LIMBS>> for PssDhPublicKey<MOD, LIMBS> {
    fn from(value: Residue<MOD, LIMBS>) -> Self {
        Self(value)
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Into<Residue<MOD, LIMBS>> for PssDhPublicKey<MOD, LIMBS> {
    fn into(self) -> Residue<MOD, LIMBS> {
        self.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> AsRef<Residue<MOD, LIMBS>> for PssDhPublicKey<MOD, LIMBS> {
    fn as_ref(&self) -> &Residue<MOD, LIMBS> {
        &self.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Deref for PssDhPublicKey<MOD, LIMBS> {
    type Target = Residue<MOD, LIMBS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> TryFrom<Box<[u8]>> for PssDhPublicKey<MOD, LIMBS> {
    type Error = ();

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Ok(Self(Residue::new(&Uint::from_be_slice(&value)).into()))
    }
}

impl<MOD: ResidueParams<LIMBS>, const LIMBS: usize> Into<Box<[u8]>> for PssDhPublicKey<MOD, LIMBS> where Uint<LIMBS>: Encoding {
    fn into(self) -> Box<[u8]> {
        self.0.retrieve().to_be_bytes().as_ref().into()
    }
}

type PkSector<const LIMBS: usize, MOD> = PssDhPublicKey<MOD, LIMBS>;

fn signature_hash<const LIMBS: usize, MOD: ResidueParams<LIMBS>, T: AsRef<[u8]>>(q: &PssDhPublicKey<MOD, LIMBS>, a1_i_sector_icc_1: Option<(PssDhPublicKey<MOD, LIMBS>, &PssDhPublicKey<MOD, LIMBS>)>, a2_i_sector_icc_2: Option<(PssDhPublicKey<MOD, LIMBS>, &PssDhPublicKey<MOD, LIMBS>)>, pk_sector: &PkSector<LIMBS, MOD>, message: &[u8]) -> GenericArray<u8, <sha3::Keccak256 as OutputSizeUser>::OutputSize>
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
pub struct GroupPssSignature<const LIMBS: usize, MOD: ResidueParams<LIMBS>>
where Uint<LIMBS>: Encoding {
    c: Uint<LIMBS>,
    s1: Uint<LIMBS>,
    s2: Uint<LIMBS>,
    pseudonyms: (Option<PssDhPublicKey<MOD, LIMBS>>, Option<PssDhPublicKey<MOD, LIMBS>>)
}

impl<const LIMBS: usize, MOD: ResidueParams<LIMBS>> PssSignature for GroupPssSignature<LIMBS, MOD>
where Uint<LIMBS> : Encoding {
    type PublicKey = PssDhPublicKey<MOD, LIMBS>;
    type Scalar = Uint<LIMBS>;

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

impl<const LIMBS: usize, MOD: ResidueParams<LIMBS>> TryFrom<GenericPssSignature> for GroupPssSignature<LIMBS, MOD>
where Uint<LIMBS> : Encoding {
    type Error = ();

    fn try_from(value: GenericPssSignature) -> Result<Self, Self::Error> {
        Ok(
            Self {
                c: Uint::from_be_slice(&value.c),
                s1: Uint::from_be_slice(&value.c),
                s2: Uint::from_be_slice(&value.c),
                pseudonyms: (
                    value.pseudonym1.map(|p| Residue::new(&Uint::from_be_slice(&p)).into()),
                    value.pseudonym2.map(|p| Residue::new(&Uint::from_be_slice(&p)).into())
                )
            }
        )
    }
}

impl<const LIMBS: usize, MOD: ResidueParams<LIMBS>> From<GroupPssSignature<LIMBS, MOD>> for GenericPssSignature
where Uint<LIMBS> : Encoding {
    fn from(value: GroupPssSignature<LIMBS, MOD>) -> Self {
        GenericPssSignature {
            c: value.c.to_be_bytes().as_ref().into(),
            s1: value.s1.to_be_bytes().as_ref().into(),
            s2: value.s2.to_be_bytes().as_ref().into(),
            pseudonym1: value.pseudonyms.0.map(|p| p.retrieve().to_be_bytes().as_ref().into()),
            pseudonym2: value.pseudonyms.1.map(|p| p.retrieve().to_be_bytes().as_ref().into())
        }
    }
}

#[derive(Debug)]
pub struct GroupPssSigner<'a, const LIMBS: usize, MOD: ResidueParams<LIMBS>>
where Uint<LIMBS>: Encoding {
    g: &'a PssDhPublicKey<MOD, LIMBS>,
    sk_icc_1_u: &'a Uint<LIMBS>,
    sk_icc_2_u: &'a Uint<LIMBS>,
    pk_sector: &'a PssDhPublicKey<MOD, LIMBS>,
    pk_m: &'a PssDhPublicKey<MOD, LIMBS>,
    i_sector_icc_1: Option<PssDhPublicKey<MOD, LIMBS>>,
    i_sector_icc_2: Option<PssDhPublicKey<MOD, LIMBS>>,
}

impl<'a, const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>> PssSigner for GroupPssSigner<'a, LIMBS, MOD>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    type PssSignature = GroupPssSignature<LIMBS, MOD>;

    fn sign(&self, message: &[u8]) -> GroupPssSignature<LIMBS, MOD> {
        let k1 = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        let k2 = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));

        // println!("k1 = {}, k2 = {}", k1, k2);

        let g_k1 = self.g.pow(&k1);
        let pk_m_k2 = self.pk_m.pow(&k2);
        let q = g_k1.mul(&pk_m_k2).into();

        // println!("Q = g^k1 * PK_m^k2 = {}^{} * {}^{} = {} * {} = {}", self.g.retrieve(), k1, self.pk_m.retrieve(), k2, g_k1.retrieve(), pk_m_k2.retrieve(), q.retrieve());

        let pseudonym1 = match self.i_sector_icc_1 {
            Some(ref pubkey) => Some((self.pk_sector.pow(&k1).into(), pubkey)),
            None => None
        };
        let pseudonym2 = match self.i_sector_icc_2 {
            Some(ref pubkey) => Some((self.pk_sector.pow(&k2).into(), pubkey)),
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

        GroupPssSignature {
            c,
            s1,
            s2,
            pseudonyms: (
                self.i_sector_icc_1.clone(),
                self.i_sector_icc_2.clone()
            )
        }
    }
}

pub struct GroupSectorSpecificIdentifiers<const LIMBS: usize, MOD: ResidueParams<LIMBS>> {
    i_sector_icc_1: PssDhPublicKey<MOD, LIMBS>,
    i_sector_icc_2: PssDhPublicKey<MOD, LIMBS>
}

impl<const LIMBS: usize, MOD: ResidueParams<LIMBS>> GroupSectorSpecificIdentifiers<LIMBS, MOD> {
    pub fn new(i_sector_icc_1: PssDhPublicKey<MOD, LIMBS>, i_sector_icc_2: PssDhPublicKey<MOD, LIMBS>) -> Self {
        Self { i_sector_icc_1, i_sector_icc_2 }
    }
}

#[derive(Debug)]
pub struct GroupIcc<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    gpk: GroupGroupManagerPublicKey<LIMBS, MOD>,
    sk_icc_1_u: Uint<LIMBS>,
    sk_icc_2_u: Uint<LIMBS>,
    _mod: PhantomData<MOD>
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>> Icc for GroupIcc<LIMBS, WIDE_LIMBS, MOD>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    type GroupManagerPublicKey = GroupGroupManagerPublicKey<LIMBS, MOD>;
    type SecretKey = Uint<LIMBS>;
    type SectorSpecificIdentifiers = GroupSectorSpecificIdentifiers<LIMBS, MOD>;
    type PublicKey = PssDhPublicKey<MOD, LIMBS>;
    type Signer<'a> = GroupPssSigner<'a, LIMBS, MOD>;

    fn new(gpk: GroupGroupManagerPublicKey<LIMBS, MOD>, sk_icc_1_u: Uint<LIMBS>, sk_icc_2_u: Uint<LIMBS>) -> Self {
        Self {
            gpk, sk_icc_1_u, sk_icc_2_u, _mod: PhantomData
        }
    }

    fn sector_identifiers(&self, pk_sector: &PkSector<LIMBS, MOD>) -> GroupSectorSpecificIdentifiers<LIMBS, MOD> {
        let i_sector_icc_1 = pk_sector.pow(&self.sk_icc_1_u);
        let i_sector_icc_2 = pk_sector.pow(&self.sk_icc_2_u);
        GroupSectorSpecificIdentifiers::new(i_sector_icc_1.into(), i_sector_icc_2.into())
    }

    fn signer<'a>(&'a self, pk_sector: &'a PkSector<LIMBS, MOD>, use_identifier1: bool, use_identifier2: bool) -> GroupPssSigner<'a, LIMBS, MOD> {
        let identifiers = self.sector_identifiers(pk_sector);
        let (i_sector_icc_1, i_sector_icc_2) = match (use_identifier1, use_identifier2) {
            (true, true) => (Some(identifiers.i_sector_icc_1), Some(identifiers.i_sector_icc_2)),
            (true, false) => (Some(identifiers.i_sector_icc_1), None),
            (false, true) => (None, Some(identifiers.i_sector_icc_2)),
            (false, false) => (None, None)
        };
        GroupPssSigner {
            g: &self.gpk.g,
            sk_icc_1_u: &self.sk_icc_1_u,
            sk_icc_2_u: &self.sk_icc_2_u,
            pk_sector: pk_sector,
            pk_m: &self.gpk.pk_m,
            i_sector_icc_1,
            i_sector_icc_2
        }
    }

    fn valid_for_gpk(&self, group: &GroupGroupManagerPublicKey<LIMBS, MOD>) -> bool {
        // g^sk_icc_1_u * pk_m^sk_icc_2_u == pk_icc
        let part1 = group.g.pow(&self.sk_icc_1_u);
        let part2 = group.pk_m.pow(&self.sk_icc_2_u);
        let y_self = part1.mul(&part2).retrieve();
        // println!("g1 = {:?}, g2 = {:?}, g1^x1 = {:?}, g2^x2 = {:?}, g1^x1*g2^x2 = {:?}", group.g.retrieve(), group.pk_icc.retrieve(), part1.retrieve(), part2.retrieve(), y_self);
        y_self == group.pk_icc.retrieve()
    }
    
    fn from_generic_secret_key(secret_key: crate::GenericIccSecretKey, gpk: Self::GroupManagerPublicKey) -> Self {
        Self {
            sk_icc_1_u: Uint::from_be_slice(&secret_key.sk_icc_1_u),
            sk_icc_2_u: Uint::from_be_slice(&secret_key.sk_icc_2_u),
            gpk,
            _mod: PhantomData
        }
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>> From<GroupIcc<LIMBS, WIDE_LIMBS, MOD>> for GenericIccSecretKey
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    fn from(value: GroupIcc<LIMBS, WIDE_LIMBS, MOD>) -> Self {
        Self {
            sk_icc_1_u: value.sk_icc_1_u.to_be_bytes().as_ref().into(),
            sk_icc_2_u: value.sk_icc_2_u.to_be_bytes().as_ref().into()
        }
    }
}

#[derive(Clone, Debug)]
pub struct GroupGroupManagerPublicKey<const LIMBS: usize, MOD: ResidueParams<LIMBS>> {
    g: PssDhPublicKey<MOD, LIMBS>,
    pk_icc: PssDhPublicKey<MOD, LIMBS>,
    pk_m: PssDhPublicKey<MOD, LIMBS>
}

impl<const LIMBS: usize, MOD: ResidueParams<LIMBS>> GroupManagerPublicKey for GroupGroupManagerPublicKey<LIMBS, MOD>
where Uint<LIMBS>: Encoding {
    type PublicKey = PssDhPublicKey<MOD, LIMBS>;
    type Signature = GroupPssSignature<LIMBS, MOD>;
    type Base = PssDhPublicKey<MOD, LIMBS>;

    fn new(pk_icc: PssDhPublicKey<MOD, LIMBS>, pk_m: PssDhPublicKey<MOD, LIMBS>, g: Option<PssDhPublicKey<MOD, LIMBS>>) -> Self {
        Self { g: g.unwrap(), pk_icc, pk_m }
    }

    fn check_signature(&self, message: &[u8], pk_sector: &PkSector<LIMBS, MOD>, signature: &GroupPssSignature<LIMBS, MOD>) -> bool {
        self.recover_c(message, pk_sector, signature) == signature.c
    }
    
    fn from_generic_gpk(gpk: crate::GenericGroupManagerPublicKey, g: Option<Box<[u8]>>) -> Self {
        Self {
            g: Residue::new(&Uint::from_be_slice(&g.unwrap())).into(),
            pk_icc: Residue::new(&Uint::from_be_slice(&gpk.pk_icc)).into(),
            pk_m: Residue::new(&Uint::from_be_slice(&gpk.pk_m)).into()
        }
    }
}

impl<const LIMBS: usize, MOD: ResidueParams<LIMBS>> From<GroupGroupManagerPublicKey<LIMBS, MOD>> for GenericGroupManagerPublicKey
where Uint<LIMBS>: Encoding {
    fn from(value: GroupGroupManagerPublicKey<LIMBS, MOD>) -> Self {
        Self {
            pk_icc: value.pk_icc.retrieve().to_be_bytes().as_ref().into(),
            pk_m: value.pk_m.retrieve().to_be_bytes().as_ref().into()
        }
    }
}

impl<const LIMBS: usize, MOD: ResidueParams<LIMBS>> GroupGroupManagerPublicKey<LIMBS, MOD>
where Uint<LIMBS>: Encoding {
    pub(crate) fn recover_c(&self, message: &[u8], pk_sector: &PkSector<LIMBS, MOD>, signature: &GroupPssSignature<LIMBS, MOD>) -> Uint<LIMBS> {
        let pk_icc_c = self.pk_icc.pow(&signature.c);
        let g_s1 = self.g.pow(&signature.s1);
        let pk_m_s2 = self.pk_m.pow(&signature.s2);
        let q = pk_icc_c.mul(&g_s1).mul(&pk_m_s2).into();

        // println!("Q' = PK_icc^c * g^s1 * PK_m^s2 = {} * {} * {} = {}", pk_icc_c.retrieve(), g_s1.retrieve(), pk_m_s2.retrieve(), q.retrieve());

        let pseudonym1 = match signature.pseudonyms.0 {
            Some(ref pubkey) => {
                let sector_c = pubkey.pow(&signature.c);
                let pk_s = pk_sector.pow(&signature.s1);
                let a1 = sector_c.mul(&pk_s);
                // println!("A1' = I_icc_1^c * PK_sector^s1 = {}^{} * {}^{} = {} * {} = {}", pubkey.retrieve(), signature.c, pk_sector.retrieve(), signature.s1, sector_c.retrieve(), pk_s.retrieve(), a1.retrieve());
                Some((a1.into(), pubkey))
            },
            None => None,
        };
        let pseudonym2 = match signature.pseudonyms.1 {
            Some(ref pubkey) => {
                let sector_c = pubkey.pow(&signature.c);
                let pk_s = pk_sector.pow(&signature.s2);
                let a2 = sector_c.mul(&pk_s);
                // println!("A2' = I_icc_2^c * PK_sector^s2 = {}^{} * {}^{} = {} * {} = {}", pubkey.retrieve(), signature.c, pk_sector.retrieve(), signature.s2, sector_c.retrieve(), pk_s.retrieve(), a2.retrieve());
                Some((a2.into(), pubkey))
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
pub struct GroupGroupManager<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    sk_m: Uint<LIMBS>,
    sk_icc: Uint<LIMBS>,
    gpk: GroupGroupManagerPublicKey<LIMBS, MOD>,
    sectors: Vec<(PkSector<LIMBS, MOD>, Option<Uint<LIMBS>>)>,
    _mod: PhantomData<MOD>
}



impl<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>> GroupManager for GroupGroupManager<LIMBS, WIDE_LIMBS, MOD>
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>> {
    type SecretKey = Uint<LIMBS>;
    
    type PublicKey = PssDhPublicKey<MOD, LIMBS>;
    
    type GroupManagerPublicKey = GroupGroupManagerPublicKey<LIMBS, MOD>;
    
    type Icc = GroupIcc<LIMBS, WIDE_LIMBS, MOD>;
    
    type Base = PssDhPublicKey<MOD, LIMBS>;


    fn new(g: Option<Self::Base>) -> Self {
        let g = g.unwrap();
        let sk_m = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        let sk_icc = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        Self::new_from_secret_parts(sk_m, sk_icc, Some(g))
    }

    fn new_from_secret_parts(sk_m: Self::SecretKey, sk_icc: Self::SecretKey, g: Option<Self::Base>) -> Self {
        let g = g.unwrap();
        let pk_m = g.pow(&sk_m);
        let pk_icc = g.pow(&sk_icc);
        // println!("g = {}, SK_m = {}, SK_icc = {}", g.retrieve(), sk_m, sk_icc);
        // println!("PK_m = g^SK_m = {}^{} = {}", g.retrieve(), sk_m, pk_m.retrieve());
        // println!("PK_icc = g^SK_icc = {}^{} = {}", g.retrieve(), sk_icc, pk_icc.retrieve());
        let gpk = GroupGroupManagerPublicKey::new(pk_icc.into(), pk_m.into(), Some(g.into()));
        Self { sk_m, sk_icc, gpk, sectors: Vec::new(), _mod: PhantomData }
    }

    fn renew_icc(&mut self) -> Uint<LIMBS> {
        let mut sk_icc = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        self.gpk.pk_icc = self.gpk.g.pow(&sk_icc).into();
        std::mem::swap(&mut self.sk_icc, &mut sk_icc);
        sk_icc
    }

    fn public_key(&self) -> &GroupGroupManagerPublicKey<LIMBS, MOD> {
        &self.gpk
    }

    fn new_sector(&mut self, deanonymizable: bool) -> PkSector<LIMBS, MOD> {
        let sk_sector = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        let pk_sector = PssDhPublicKey(self.gpk.g.pow(&sk_sector));

        // println!("SK_sector = {}", sk_sector);
        // println!("PK_sector = g^SK_sector = {}^{} = {}", self.gpk.g.retrieve(), sk_sector, pk_sector.retrieve());

        self.sectors.push((pk_sector.clone(), match deanonymizable {
            true => Some(sk_sector),
            false => None
        }));
        pk_sector
    }

    fn new_icc(&self) -> GroupIcc<LIMBS, WIDE_LIMBS, MOD> {
        let sk_icc_2_u = Uint::<LIMBS>::random_mod(&mut OsRng::default(), &NonZero::from_uint(MOD::MODULUS));
        // SK_ICC_1 = SK_ICC - SK_M * SK_ICC_2
        let fermat_modulus = MOD::MODULUS.checked_sub(&Uint::from_u8(1)).unwrap();
        let multiplication = mul_mod(&self.sk_m, &sk_icc_2_u, &fermat_modulus);
        let sk_icc_1_u = self.sk_icc.sub_mod(&multiplication, &fermat_modulus);

        // println!("SK_icc_2 = {}, fermat_modulus = {}", sk_icc_2_u, fermat_modulus);
        // println!("SK_icc_1 = SK_icc - SK_m * SK_icc_2 = {} - {} * {} = {} - {} = {}", self.sk_icc, self.sk_m, sk_icc_2_u, self.sk_icc, multiplication, sk_icc_1_u);
        GroupIcc::new(self.gpk.clone(), sk_icc_1_u, sk_icc_2_u)
    }
    
    fn from_generic_secret_key(secret_key: crate::GenericGroupManagerPrivateKey, g: Option<Box<[u8]>>) -> Self {
        let sk_m = Uint::from_be_slice(&secret_key.sk_m);
        let sk_icc = Uint::from_be_slice(&secret_key.sk_icc);
        let g = Residue::new(&Uint::from_be_slice(&g.unwrap()));
        Self::new_from_secret_parts(sk_m, sk_icc, Some(g.into()))
    }

}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, MOD: ResidueParams<LIMBS>> From<GroupGroupManager<LIMBS, WIDE_LIMBS, MOD>> for GenericGroupManagerPrivateKey
where Uint<LIMBS>: Encoding + ConcatMixed<MixedOutput = Uint<WIDE_LIMBS>>, Uint<WIDE_LIMBS>: SplitMixed<Uint<LIMBS>, Uint<LIMBS>>{
    fn from(value: GroupGroupManager<LIMBS, WIDE_LIMBS, MOD>) -> Self {
        Self {
            sk_m: value.sk_m.to_be_bytes().as_ref().into(),
            sk_icc: value.sk_icc.to_be_bytes().as_ref().into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGN_MESSAGE: &[u8] = b"TEST MESSAGE";

    #[test]
    fn valid_signature() {
        let mut group_manager = GroupGroupManager::new(Some(DH_MODP_2048));
        let icc = group_manager.new_icc();
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
        let mut group_manager = GroupGroupManager::new(Some(DH_MODP_2048));
        let nym = group_manager.new_icc();
        let sector = group_manager.new_sector(false);

        let combinations = vec![(true, true), (true, false), (false, true), (false, false)];
        for (id1, id2) in combinations {
            let signer = nym.signer(&sector, id1, id2);
            let signature = signer.sign(SIGN_MESSAGE);
            fn tamper_with<const LIMBS: usize, MOD: ResidueParams<LIMBS>>(signature: &mut GroupPssSignature<LIMBS, MOD>, c: bool, s1: bool, s2: bool)
            where Uint<LIMBS> : Encoding {
                if c {
                    signature.c = signature.c.wrapping_sub(&Uint::from_u8(1));
                }
                if s1 {
                    signature.s1 = signature.s1.wrapping_sub(&Uint::from_u8(1));
                }
                if s2 {
                    signature.s2 = signature.s2.wrapping_sub(&Uint::from_u8(1));
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
    fn valid_keys() {
        let mut group_manager = GroupGroupManager::new(Some(DH_MODP_2048));
        let nym = group_manager.new_icc();
        assert!(nym.valid_for_gpk(group_manager.public_key()));

        let _ = group_manager.renew_icc();
        assert!(!nym.valid_for_gpk(group_manager.public_key()));
    }
}
