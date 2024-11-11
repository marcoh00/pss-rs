use clap::{builder::EnumValueParser, value_parser, Arg, ArgAction, Command, ValueEnum};
use pss_rs::{
    ecc::{EccGroupManager, PssCompatibleEccCurve},
    rustcryptoecc::PssSecp256k1,
    GenericGroupManagerPrivateKey, GenericGroupManagerPublicKey, GroupManager,
    GroupManagerPublicKey, Icc, PssSignature, PssSigner,
};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use std::{fs::File, path::PathBuf};

#[cfg(feature = "altbn")]
use pss_rs::altbn::PssAltBn128;

#[derive(Debug, Clone, ValueEnum)]
pub enum Algorithm {
    Secp256k1,
    #[cfg(feature = "altbn")]
    AltBn128,
    #[cfg(feature = "dh")]
    DH2048,
}

impl Algorithm {
    pub fn to_sol_name(&self) -> &str {
        match self {
            Algorithm::Secp256k1 => "PssSecp256k1",
            #[cfg(feature = "altbn")]
            Algorithm::AltBn128 => "PssAltBn128",
            #[cfg(feature = "dh")]
            DH2048 => "unsupported",
        }
    }
}

#[derive(Serialize)]
struct SectorKey {
    pk_sector: Box<[u8]>,
    pk_sector_x: String,
    pk_sector_y: String,
}

#[derive(Serialize)]
struct Key {
    sk_m: Box<[u8]>,
    pk_m: Box<[u8]>,
    pk_m_x: String,
    pk_m_y: String,
    sk_icc: Box<[u8]>,
    pk_icc: Box<[u8]>,
    pk_icc_x: String,
    pk_icc_y: String,
    sectors: Vec<SectorKey>,
    algorithm: String,
}

fn main() {
    let cmd = Command::new("pss-keygen")
        .bin_name("pss-keygen")
        .about("Generate Keypairs for the Pseudonymous Signature Scheme (PSS)")
        .arg(
            Arg::new("algorithm")
                .short('a')
                .value_parser(EnumValueParser::<Algorithm>::new())
                .default_value("secp256k1"),
        )
        .arg(
            Arg::new("sectors")
                .help("Number of sector keys to generate")
                .short('s')
                .default_value("1")
                .value_parser(value_parser!(u16)),
        )
        .arg(
            Arg::new("force")
                .help("Overwrite output file if neccessary")
                .short('f')
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("contract")
                .help("Output Ethereum Test Contract to stdout")
                .short('c')
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        );
    let matches = cmd.get_matches();
    let algorithm: &Algorithm = matches
        .get_one("algorithm")
        .expect("specified algorithm on command line");
    let sectors: &u16 = matches
        .get_one("sectors")
        .expect("specified number of sectors on command line");
    let outpath: &PathBuf = matches
        .get_one("output")
        .expect("specified output file on command line");
    let outfile = match matches.get_one::<bool>("force").unwrap() {
        true => File::create(outpath).expect("path must be writable"),
        false => {
            assert!(!outpath.exists(), "file must not exist");
            File::create(outpath).expect("path must be writable")
        }
    };

    let key = generate_keys(
        algorithm,
        sectors,
        matches.get_one::<bool>("contract").unwrap(),
    );
    serde_json::to_writer_pretty(outfile, &key).expect("key is valid and can be serialized");
}

fn generate_keys(algorithm: &Algorithm, sectors: &u16, contract: &bool) -> Key {
    match algorithm {
        Algorithm::Secp256k1 => generate_keys_ecc::<PssSecp256k1>(algorithm, *sectors, *contract),
        #[cfg(feature = "altbn")]
        Algorithm::AltBn128 => generate_keys_ecc::<PssAltBn128>(algorithm, *sectors, *contract),
        #[cfg(feature = "dh")]
        Algorithm::DH2048 => {
            todo!()
        }
    }
}

fn generate_keys_ecc<C: PssCompatibleEccCurve>(
    algorithm: &Algorithm,
    sectors: u16,
    contract: bool,
) -> Key {
    let mut gm: EccGroupManager<C> = EccGroupManager::new(None);
    let mut test_cases = Vec::new();
    let sectors = (0..sectors)
        .map(|i| {
            let sector = gm.new_sector(false);
            if contract {
                test_cases.extend(generate_eth_testcase(&gm, &sector, i))
            }
            sector.into()
        })
        .map(|pk_sector: Box<[u8]>| {
            let (pk_sector_x, pk_sector_y) = point_to_hex_str(&pk_sector);
            SectorKey {
                pk_sector,
                pk_sector_x,
                pk_sector_y,
            }
        })
        .collect::<Vec<_>>();
    let pubkey: GenericGroupManagerPublicKey = gm.public_key().clone().into();
    let privkey: GenericGroupManagerPrivateKey = gm.into();
    let (pk_m_x, pk_m_y) = point_to_hex_str(&pubkey.pk_m);
    let (pk_icc_x, pk_icc_y) = point_to_hex_str(&pubkey.pk_icc);

    let key = Key {
        algorithm: <Algorithm as ValueEnum>::to_possible_value(algorithm)
            .unwrap()
            .get_name()
            .to_owned(),
        sk_m: privkey.sk_m,
        pk_m: pubkey.pk_m,
        pk_m_x,
        pk_m_y,
        sk_icc: privkey.sk_icc,
        pk_icc: pubkey.pk_icc,
        pk_icc_x,
        pk_icc_y,
        sectors,
    };

    if contract {
        generate_eth(&test_cases, &key, algorithm);
    }

    key
}

fn point_to_hex_str(point_repr: &[u8]) -> (String, String) {
    assert_ne!(
        point_repr.len() % 2,
        0,
        "Point must have an even length plus the sec1 prefix"
    );
    assert_eq!(
        point_repr[0], 4,
        "first byte must be 0x04 to indicate an uncompressed representation"
    );
    let point_repr = &point_repr[1..];

    let hex_chars_per_side = point_repr.len(); // * 2 for # of hex chars / 2 for half
    let mut hex = slice_to_hex_str(point_repr);
    let second = hex.split_off(hex_chars_per_side);
    (hex, second)
}

fn slice_to_hex_str(slice: &[u8]) -> String {
    slice
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

fn generate_eth(test_cases: &Vec<String>, key: &Key, algorithm: &Algorithm) {
    println!("// SPDX-License-Identifier: UNLICENSED");
    println!("pragma solidity ^0.8.13;");
    println!();
    println!("import {{Test, console}} from \"forge-std/Test.sol\";");
    println!("import \"../src/{}.sol\";", algorithm.to_sol_name());
    println!();
    println!("contract CONTRACTNAME is Test {{");
    println!("    {} public pss;", algorithm.to_sol_name());
    println!();
    println!("    function setUp() public {{");
    println!("        uint256 pk_m_x = 0x{};", key.pk_m_x);
    println!("        uint256 pk_m_y = 0x{};", key.pk_m_y);
    println!("        uint256 pk_icc_x = 0x{};", key.pk_icc_x);
    println!("        uint256 pk_icc_y = 0x{};", key.pk_icc_y);
    println!(
        "        uint256 pk_sector_x = 0x{};",
        key.sectors.get(0).unwrap().pk_sector_x
    );
    println!(
        "        uint256 pk_sector_y = 0x{};",
        key.sectors.get(0).unwrap().pk_sector_y
    );
    println!("        pss = new {}(ECC.Point(pk_m_x, pk_m_y), ECC.Point(pk_icc_x, pk_icc_y), ECC.Point(pk_sector_x, pk_sector_y));", algorithm.to_sol_name());
    println!("    }}");
    println!();
    println!("{}", test_cases.join("\n"));
    println!("}}");
}

fn generate_eth_testcase<C: PssCompatibleEccCurve>(
    gpk: &EccGroupManager<C>,
    sector: &C::Point,
    sector_number: u16,
) -> impl Iterator<Item = String> {
    let mut test_cases = Vec::new();
    let icc = gpk.new_icc();
    for comb in 0..4 {
        // TODO REMOVE
        println!("----------------- COMB {:02} ------------------", comb);
        let use_identifier1 = (comb & 1) > 0;
        let use_identifier2 = (comb & 2) > 0;
        let signer = icc.signer(sector, use_identifier1, use_identifier2);
        let message = generate_message();
        let signature = signer.sign(&message);
        let c: Box<[u8]> = signature.c().clone().into();
        let s1: Box<[u8]> = signature.s1().clone().into();
        let s2: Box<[u8]> = signature.s2().clone().into();
        let i_sector_icc_1 = match use_identifier1 {
            true => Some(signature.pseudonym1().clone().unwrap().into()),
            false => None,
        };
        let i_sector_icc_2 = match use_identifier2 {
            true => Some(signature.pseudonym2().clone().unwrap().into()),
            false => None,
        };
        println!(
            "Signature check: {}",
            gpk.public_key()
                .check_signature(&message, sector, &signature)
        );
        test_cases.extend(contract_test_case(
            sector_number,
            &message,
            c,
            s1,
            s2,
            i_sector_icc_1,
            i_sector_icc_2,
        ));
    }
    test_cases.into_iter()
}

fn generate_message() -> Vec<u8> {
    let mut rng = OsRng::default();
    // Number of bytes: max. 32, min. 4
    let number_of_bytes = loop {
        let number = ((rng.next_u32() & 0x1F) + 1) as usize;
        if number > 4 {
            break number;
        }
    };
    let mut message = vec![0; number_of_bytes];
    rng.fill_bytes(&mut message);
    message
}

fn contract_test_case(
    sector: u16,
    message: &[u8],
    c: Box<[u8]>,
    s1: Box<[u8]>,
    s2: Box<[u8]>,
    i_sector_icc_1: Option<Box<[u8]>>,
    i_sector_icc_2: Option<Box<[u8]>>,
) -> impl Iterator<Item = String> {
    let msg_len = message.len();
    let (name_suffix, lines_needed, params) =
        match (i_sector_icc_1.is_some(), i_sector_icc_2.is_some()) {
            (false, false) => ("", 0, ""),
            (false, true) => ("_p2", 1, ", i_sector_icc_2"),
            (true, false) => ("_p1", 1, ", i_sector_icc_1"),
            (true, true) => ("_p1_p2", 2, ", i_sector_icc_1, i_sector_icc_2"),
        };
    let mut lines = Vec::with_capacity(1 + 1 + msg_len + 3 + lines_needed + 2);
    lines.push(format!(
        "    function test_validate_signature_sector_{}{}() public {{",
        sector, name_suffix
    ));
    lines.push(format!(
        "        bytes memory message = new bytes({});",
        msg_len
    ));
    for i in 0..msg_len {
        lines.push(format!(
            "        message[{}] = 0x{};",
            i,
            slice_to_hex_str(&[message[i]])
        ));
    }
    lines.push(format!("        uint256 c = 0x{};", slice_to_hex_str(&c)));
    lines.push(format!("        uint256 s1 = 0x{};", slice_to_hex_str(&s1)));
    lines.push(format!("        uint256 s2 = 0x{};", slice_to_hex_str(&s2)));
    for (i, sector) in [i_sector_icc_1, i_sector_icc_2].into_iter().enumerate() {
        if let Some(sector_key) = sector {
            let (x, y) = point_to_hex_str(&sector_key);
            lines.push(format!(
                "        ECC.Point memory i_sector_icc_{} = ECC.Point(0x{}, 0x{});",
                i + 1,
                x,
                y
            ));
        }
    }
    lines.push(format!(
        "        assertTrue(pss.validate_signature{}(message, c, s1, s2{}));",
        name_suffix, params
    ));
    lines.push("    }".into());
    lines.into_iter()
}
