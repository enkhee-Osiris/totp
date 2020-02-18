use super::{
    HashFunction, DEFAULT_TOTP_HASH, DEFAULT_TOTP_OUT_LEN, DEFAULT_TOTP_PERIOD, DEFAULT_TOTP_T0,
};

use base32;
use base64;
use hex;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use time;

macro_rules! compute_hmac {
    ($obj: ident, $hash: ty, $input: ident) => {{
        let mut hmac = Hmac::<$hash>::new_varkey(&$obj.secret.as_slice()).unwrap();
        hmac.input(&$input);

        hmac.result().code().to_vec()
    }};
}

pub struct TOTP {
    secret: Vec<u8>,
    initial_time: u64,
    period: u32,
    output_len: usize,
    hash_function: HashFunction,
}

impl Default for TOTP {
    fn default() -> Self {
        Self::new()
    }
}

impl TOTP {
    fn truncate(&self, hash: &[u8]) -> u32 {
        let offset = (hash[hash.len() - 1] & 0xf) as usize;
        let binary: u32 = ((u32::from(hash[offset]) & 0x7f) << 24)
            | ((u32::from(hash[offset + 1]) & 0xff) << 16)
            | ((u32::from(hash[offset + 2]) & 0xff) << 8)
            | (u32::from(hash[offset + 3]) & 0xff);

        binary % 10u32.pow(self.output_len as u32)
    }

    // TODO: Return Result
    fn get_counter(&self) -> u64 {
        let timestamp = time::PrimitiveDateTime::now().timestamp() as u64;
        if timestamp < self.initial_time {
            panic!("The current Unix time is below the initial time.");
        }

        (timestamp - self.initial_time) / u64::from(self.period)
    }

    pub fn new() -> TOTP {
        TOTP {
            secret: Vec::new(),
            initial_time: DEFAULT_TOTP_T0,
            period: DEFAULT_TOTP_PERIOD,
            output_len: DEFAULT_TOTP_OUT_LEN,
            hash_function: DEFAULT_TOTP_HASH,
        }
    }

    pub fn secret(&mut self, secret: &[u8]) -> &mut TOTP {
        self.secret = secret.to_owned();

        self
    }

    pub fn ascii_secret(&mut self, secret: &str) -> &mut TOTP {
        self.secret = secret.as_bytes().to_vec();

        self
    }

    // TODO: Return Result
    pub fn hex_secret(&mut self, secret: &str) -> &mut TOTP {
        match hex::decode(secret) {
            Ok(k) => {
                self.secret = k;
            }
            Err(_) => {}
        }

        self
    }

    // TODO: Return Result
    pub fn base32_secret(&mut self, secret: &str) -> &mut TOTP {
        match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret) {
            Some(k) => {
                self.secret = k;
            }
            None => {}
        }

        self
    }

    // TODO: Return Result
    pub fn base64_secret(&mut self, secret: &str) -> &mut TOTP {
        match base64::decode(secret) {
            Ok(k) => {
                self.secret = k;
            }
            Err(_) => {}
        }

        self
    }

    pub fn initial_time(&mut self, initial_time: u64) -> &mut TOTP {
        self.initial_time = initial_time;

        self
    }

    pub fn period(&mut self, period: u32) -> &mut TOTP {
        self.period = period;

        self
    }

    pub fn output_len(&mut self, output_len: usize) -> &mut TOTP {
        self.output_len = output_len;

        self
    }

    pub fn hash_function(&mut self, hash_function: HashFunction) -> &mut TOTP {
        self.hash_function = hash_function;

        self
    }

    // TODO: Return Result
    pub fn generate(&mut self) -> String {
        let counter = self.get_counter().to_be_bytes();

        let hash: Vec<u8> = match self.hash_function {
            HashFunction::Sha1 => compute_hmac!(self, Sha1, counter),
            HashFunction::Sha256 => compute_hmac!(self, Sha256, counter),
            HashFunction::Sha512 => compute_hmac!(self, Sha512, counter),
        };
        let mut otp: String = self.truncate(&hash).to_string();

        while otp.len() != self.output_len {
            otp = ["0", &otp].concat();
        }

        otp
    }
}
