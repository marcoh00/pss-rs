use std::{fs::File, path::PathBuf};

use clap::{builder::EnumValueParser, value_parser, Arg, ArgAction, Command, ValueEnum};
use pss_rs::{
    ecc::{EccGroupManager, PssCompatibleEccCurve},
    rustcryptoecc::PssSecp256k1,
    GenericGroupManagerPrivateKey, GenericGroupManagerPublicKey, GroupManager,
};
use serde::Serialize;

#[derive(Debug, Clone, ValueEnum)]
pub enum Algorithm {
    Secp256k1,
    #[cfg(feature = "dh")]
    DH2048,
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
                .default_value("0")
                .value_parser(value_parser!(u16)),
        )
        .arg(
            Arg::new("force")
                .help("Overwrite output file if neccessary")
                .short('f')
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
        },
    };

    let key = generate_keys(algorithm, sectors);
    serde_json::to_writer_pretty(outfile, &key).expect("key is valid and can be serialized");
}

fn generate_keys(algorithm: &Algorithm, sectors: &u16) -> Key {
    match algorithm {
        Algorithm::Secp256k1 => generate_keys_ecc::<PssSecp256k1>(algorithm, *sectors),
    }
}

fn generate_keys_ecc<C: PssCompatibleEccCurve>(algorithm: &Algorithm, sectors: u16) -> Key {
    let mut gm: EccGroupManager<C> = EccGroupManager::new(None);
    let sectors = (0..sectors)
        .map(|_| gm.new_sector(false).into())
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
    Key {
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
    }
}

fn point_to_hex_str(point_repr: &[u8]) -> (String, String) {
    assert!(
        point_repr.len() % 2 != 0,
        "Point must have an even length plus the sec1 prefix"
    );
    assert!(
        point_repr[0] == 4,
        "first byte must be 0x04 to indicate an uncompressed representation"
    );
    let point_repr = &point_repr[1..];

    let hex_chars_per_side = point_repr.len(); // * 2 for # of hex chars / 2 for half
    let mut hex = point_repr
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    let second = hex.split_off(hex_chars_per_side);
    (hex, second)
}
