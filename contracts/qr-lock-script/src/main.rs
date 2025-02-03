#![cfg_attr(not(any(feature = "native-simulator", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "native-simulator", test))]
extern crate alloc;

#[cfg(not(any(feature = "native-simulator", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "native-simulator", test)))]
ckb_std::default_alloc!();

mod error;

use crate::error::Error;
use blake2b_ref::{Blake2b, Blake2bBuilder};
use ckb_std::ckb_constants::*;
use ckb_std::ckb_types::bytes::Bytes;
use ckb_std::ckb_types::prelude::*;
use ckb_std::debug;
use ckb_std::error::SysError;
use ckb_std::high_level::*;
use fips205::slh_dsa_shake_128f;
use fips205::traits::{SerDes, Verifier};

type H256 = [u8; 32];

const BLAKE2B_BLOCK_SIZE: usize = 32;
const QR_LOCK_WITNESS_LEN: usize = 17088 + 32;

fn new_blake2b() -> Blake2b {
    const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}

// the lockscript argument is the hash of sphincs+ pubkey
fn get_pubkey_hash() -> Result<H256, SysError> {
    let lock_script = load_script()?;
    let args = lock_script.args().raw_data();
    // the last 32 bytes is the public key
    if args.len() < 32 {
        return Err(SysError::Encoding);
    }
    let mut pubkey_hash: H256 = [0u8; 32];
    pubkey_hash.copy_from_slice(&args[args.len() - 32..]);

    Ok(pubkey_hash)
}

fn generate_sig_hash_all() -> Result<H256, Error> {
    let tx_hash = load_tx_hash()?;

    // load signature - the first input's witness
    let signature: Bytes = load_witness_args(0, Source::GroupInput)?
        .lock()
        .to_opt()
        .ok_or(Error::InvalidWitnessArgs)?
        .unpack();
    let signature_len = signature.len();

    let mut blake2b = new_blake2b();
    // step 1 - hash the tx's hash
    blake2b.update(&tx_hash);
    // step 2 - hash the first witness's length
    blake2b.update(&signature_len.to_le_bytes());

    let mut index = 1;
    loop {
        let result = load_witness_args(index, Source::Input);
        match result {
            Ok(args) => {
                let buff: Bytes = args.lock().to_opt().ok_or(Error::InvalidWitnessLock)?.unpack();
                let buff_size = buff.len();
                // step 3 - hash len and witness of all inputs
                blake2b.update(&buff_size.to_le_bytes());
                blake2b.update(&buff);
            }
            Err(err) if err == SysError::IndexOutOfBound => break,
            Err(e) => {
                debug!("load_witness_args() failed at input index {}: {:?}", index, e);
                return Err(Error::from(e));
            }
        }
        index += 1;
    }

    let mut message = [0 as u8; BLAKE2B_BLOCK_SIZE];
    blake2b.finalize(&mut message);

    Ok(message)
}

fn get_sign_info() -> Result<Bytes, Error> {
    // load signature - the first input's witness
    let signature: Bytes = load_witness_args(0, Source::GroupInput)?
        .lock()
        .to_opt()
        .ok_or(Error::InvalidWitnessArgs)?
        .unpack();
    let signature_len = signature.len();
    if signature_len != QR_LOCK_WITNESS_LEN {
        return Err(Error::LengthNotEnough);
    }
    Ok(signature)
}

pub fn program_entry() -> i8 {
    let pubkey_hash = match get_pubkey_hash() {
        Ok(val) => val,
        Err(e) => return Error::from(e) as i8,
    };
    let message = match generate_sig_hash_all() {
        Ok(val) => val,
        Err(e) => return Error::from(e) as i8,
    };
    let signature = match get_sign_info() {
        Ok(val) => val,
        Err(e) => return Error::from(e) as i8,
    };
    let pubkey: H256 = signature[QR_LOCK_WITNESS_LEN - 32..]
        .try_into()
        .expect("Pubkey slice must be exactly 32 bytes");

    // verify if public key provided in the signature
    // matches the hashed pubkey in lock script's argument
    let mut blake2b = new_blake2b();
    blake2b.update(&pubkey);
    let mut pubkey_hashed = [0 as u8; BLAKE2B_BLOCK_SIZE];
    blake2b.finalize(&mut pubkey_hashed);
    if pubkey_hash != pubkey_hashed {
        return Error::InvalidSignature as i8;
    }

    // verify sphincs+ signature
    let fips205_sig: [u8; 17088] = signature[0..17088]
        .try_into()
        .expect("Signature must be exactly 17088 bytes");

    match slh_dsa_shake_128f::PublicKey::try_from_bytes(&pubkey) {
        Ok(pk) => {
            let result = pk.verify(&message, &fips205_sig, &[]);
            if !result {
                return Error::SphincsPlusVerify as i8;
            }
        }
        Err(_) => return Error::SphincsPlusInvalidPubKey as i8,
    };

    0
}
