#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

use std::fmt;
use std::str::FromStr;

pub enum HashFunctionError {
    ImportError,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum HashFunction {
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
}

impl fmt::Display for HashFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HashFunction::Sha1 => "SHA1",
            HashFunction::Sha256 => "SHA256",
            HashFunction::Sha512 => "SHA512",
        };

        write!(f, "{}", s)
    }
}

impl FromStr for HashFunction {
    type Err = HashFunctionError;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        Ok(match data.to_lowercase().as_str() {
            "sha1" => HashFunction::Sha1,
            "sha256" => HashFunction::Sha256,
            "sha512" => HashFunction::Sha512,
            _ => {
                return Err(HashFunctionError::ImportError);
            }
        })
    }
}

const DEFAULT_TOTP_HASH: HashFunction = HashFunction::Sha1;
const DEFAULT_TOTP_OUT_LEN: usize = 6;
const DEFAULT_TOTP_PERIOD: u32 = 30;
const DEFAULT_TOTP_T0: u64 = 0;

pub mod totp;
