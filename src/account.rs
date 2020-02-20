use rand::prelude::*;
use rand::thread_rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
use std::fmt;

pub struct Account {
    priv_key: Vec<u8>,
    pub_key: Vec<u8>,
    address: Vec<u8>,
}

impl Account {
    pub fn new(priv_key_bytes: &[u8]) -> Account {
        let secp = Secp256k1::new();
        let priv_key = SecretKey::from_slice(priv_key_bytes).expect("error generating private_key");
        let pub_key = PublicKey::from_secret_key(&secp, &priv_key);
        let pub_key = &pub_key.serialize_uncompressed()[1..];

        let mut hasher = Keccak256::new();
        hasher.input(pub_key);
        let address = &hasher.result()[12..];

        Account {
            priv_key: Vec::from(priv_key_bytes),
            pub_key: Vec::from(pub_key),
            address: Vec::from(address),
        }
    }

    pub fn rand_new() -> Account {
        let mut pk_src: [u8; 32] = [0; 32];
        let mut generator = thread_rng();
        generator.fill_bytes(&mut pk_src);
        Account::new(&pk_src)
    }

    pub fn priv_key_as_hex(&self) -> String {
        byte_array_to_hex_prefixed(&self.priv_key)
    }

    pub fn pub_key_as_hex(&self) -> String {
        byte_array_to_hex_prefixed(&self.pub_key)
    }

    pub fn address_as_hex(&self) -> String {
        byte_array_to_hex_prefixed(&self.address)
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "private key: {:?}\n public key: {:?}\n address: {:?}\n",
            self.priv_key, self.pub_key, self.address
        )
    }
}

impl fmt::LowerHex for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "private key: {}\n public key: {}\n address: {}\n",
            &self.priv_key_as_hex(),
            &self.pub_key_as_hex(),
            &self.address_as_hex(),
        )
    }
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "private key: {} len: {}\n public key: {} len: {}\n address: {} len: {}\n",
            byte_array_to_hex_prefixed(&self.priv_key),
            &self.priv_key.len(),
            byte_array_to_hex_prefixed(&self.pub_key),
            &self.pub_key.len(),
            byte_array_to_hex_prefixed(&self.address),
            &self.address.len(),
        )
    }
}

fn byte_array_to_hex(u8_vector: &Vec<u8>) -> String {
    u8_vector
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}

fn byte_array_to_hex_prefixed(u8_vector: &Vec<u8>) -> String {
    format!("{}{}", "0x", byte_array_to_hex(u8_vector))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::thread_rng;
    use regex::Regex;

    const EMPTY_PK: [u8; 32] = [0; 32];

    fn addr_rgx() -> Regex {
        Regex::new("^0x[0-9a-fA-F]+$").unwrap()
    }

    fn rand_gen() -> StdRng {
        StdRng::from_rng(thread_rng()).unwrap()
    }

    fn check_account_properties(account: &Account) {
        let priv_key = account.priv_key_as_hex();
        let pub_key = account.pub_key_as_hex();
        let address = account.address_as_hex();

        assert!(
            addr_rgx().is_match(&priv_key),
            "private key should be hexadecimal."
        );
        assert_eq!(
            priv_key.len(),
            66,
            "private key should be 66 characters long but was {} characters long.",
            priv_key.len()
        );

        assert!(
            addr_rgx().is_match(&pub_key),
            "public key key should be hexadecimal."
        );
        assert_eq!(
            pub_key.len(),
            130,
            "public key should be 130 characters long but was {} characters long.",
            pub_key.len()
        );

        assert!(
            addr_rgx().is_match(&address),
            "address key should be hexadecimal."
        );
        assert_eq!(
            address.len(),
            42,
            "address should be 22 characters long but was {} characters long.",
            address.len()
        );
    }

    #[test]
    fn test_new_account() {
        let mut pk = EMPTY_PK;
        rand_gen().fill_bytes(&mut pk);

        let account = Account::new(&pk);

        check_account_properties(&account);
    }

    #[test]
    fn test_new_account_multiple() {
        let mut pk = EMPTY_PK;
        let mut rand = rand_gen();

        rand.fill_bytes(&mut pk);
        let account = Account::new(&pk);
        check_account_properties(&account);

        rand.fill_bytes(&mut pk);
        let account = Account::new(&pk);
        check_account_properties(&account);
    }

    #[test]
    fn test_rand_new_account() {
        let account = Account::rand_new();

        check_account_properties(&account);
    }

    #[test]
    fn test_rand_new_account_multiple() {
        let account = Account::rand_new();
        check_account_properties(&account);

        let account = Account::rand_new();
        check_account_properties(&account);
    }
}
