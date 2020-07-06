use std::convert::TryInto;
use anyhow::Result;
use secrecy::{ExposeSecret, Secret, SecretString};
use tai64::TAI64N;
use custom_codes::AccessStatus;

use crate::global::{Role, TaiTimeStamp, Lease};

#[derive(Debug)]
pub struct Blake3Token {
    username: SecretString,
    timestamp: Secret<TaiTimeStamp>,
    lease: Secret<Lease>,
    role: Secret<Role>,
    //access_control: Vec<Secret<AccessControlList>>,
    //scheme_control: Vec<Secret<SchemeControlList>>,
}

//FIXME convert this into a feature that cab be activated in debug env
impl secrecy::DebugSecret for Blake3Token {}

impl Blake3Token {
    pub fn new() -> Blake3Token {
        Self {
            username: SecretString::new("".into()),
            /// Automatically generated and is not available for modofication
            timestamp: Secret::new(TaiTimeStamp::now()),
            lease: Secret::new(Lease::default()),
            role: Secret::new(Role::User),
            //access_control: Vec::default(), //TODO 
            //scheme_control: Vec::default(), //TODO
        }
    }

    pub fn username(&mut self, value: SecretString) -> &mut Blake3Token {
        self.username = value;

        self
    }

    pub (crate) fn lease(&mut self, value: Secret<Lease>) -> &mut Blake3Token {
        self.lease = value;

        self
    }

    pub fn role(&mut self, value: Secret<Role>) -> &mut Blake3Token {
        self.role = value;

        self
    }
    /// Get back a borrowed `Blake3Token`
    pub fn build(&self) -> &Blake3Token {

        self
    }
    /// Get the current blake3 hash of the token contents
   pub async fn get_hash(&self) -> Result<SecretString> {

        let mut conf = crate::SchemeGuardianConfig::new();
        conf.init().await?;
        let key: [u8; 32] = conf.secrets.default.expose_secret().as_bytes().try_into()?;
        let mut data = blake3::Hasher::new_keyed(&key);

        data.update(&self.username.expose_secret().as_bytes());
        data.update(&self.timestamp.expose_secret().get_bytes().expose_secret());
        data.update(&Lease::to_header(&self.lease.expose_secret()));
        data.update(&Role::from_header(&self.role.expose_secret()));
        let blake3hash = data.finalize();

        Ok(SecretString::new(hex::encode(blake3hash.as_bytes())))
    }
    /// Transform `hex` value into `blake3::Hash`
    pub fn to_blake3(hex: &SecretString) -> Result<blake3::Hash> {
        let hash_bytes = hex::decode(hex.expose_secret())?;
        let hash_array: [u8; blake3::OUT_LEN] = hash_bytes[..].try_into()?;
        let hash: blake3::Hash = hash_array.into();

        Ok(hash)
    }

    fn check_lease(&self) -> AccessStatus {    
        // TODO Check if there is need for constant-time comparison    
        match self.lease.expose_secret() {
            &Lease::DateExpiryTAI(tai_time) => {
                if TAI64N::now() >= tai_time {
                    AccessStatus::Expired
                }else {
                    AccessStatus::Granted
                }
            },
            _ => AccessStatus::Denied
        }
    }

    fn check_role(&self, role_guard: Secret<Role>) -> AccessStatus {
        // TODO Check if there is need for constant-time comparison
        let role = self.role.expose_secret();
        
        if role == role_guard.expose_secret() {
            AccessStatus::Granted
        }else {
            AccessStatus::Rejected
        }
    }
}