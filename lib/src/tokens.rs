use aead::{generic_array::GenericArray, Aead, NewAead};
use anyhow::Result;
use chacha20poly1305::XChaCha20Poly1305;
use secrecy::{ExposeSecret, Secret, SecretString};
use serde::{Deserialize, Serialize};
use tai64::TAI64N;
use data_encoding::{BASE64URL_NOPAD};
use custom_codes::AccessStatus;

use crate::global::{AccessControlList, Role, TaiTimeStamp, Lease};

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenContents {
    username: SecretString,
    proof: SecretString,
    timestamp: Secret<TaiTimeStamp>,
    lease: Secret<Lease>,
    role: Secret<Role>,
    access_control: Vec<Secret<AccessControlList>>,
    //scheme_control: Vec<Secret<SchemeControlList>>,
}

impl secrecy::DebugSecret for TokenContents {}

impl TokenContents {
    pub async fn new() -> Self {
        Self {
            username: SecretString::new("".into()),
            proof: crate::random24alpha().await,
            /// Automatically generated and is not available for modofication
            timestamp: Secret::new(TaiTimeStamp::now()),
            lease: Secret::new(Lease::Unspecified),
            role: Secret::new(Role::Unspecified),
            access_control: Vec::default(), //TODO 
            //scheme_control: Vec::default(), //TODO 
        }
    }

    pub async fn username(&mut self, value: SecretString) -> &mut Self {
        self.username = value;

        self
    }

    pub async fn lease(&mut self, value: Secret<Lease>) -> &mut Self {
        self.lease = value;

        self
    }

    pub async fn role(&mut self, value: Secret<Role>) -> &mut Self {
        self.role = value;

        self
    }

    pub async fn acl(&mut self, value: Secret<AccessControlList>) -> &mut Self {
        self.access_control.push(value);

        self
    }

    pub async fn build(&self) -> &Self {

        self
    }

    pub async fn swap(&mut self, value: &Self) -> &Self {
        self.username = value.username.clone();
        self.proof = value.proof.clone();
        self.timestamp = value.timestamp.clone();
        self.lease = value.lease.clone();
        self.role = value.role.clone();
        self.access_control = value.access_control.clone();

        self
    }

    pub async fn get_proof(&self) -> &SecretString {

        &self.proof
    }

    pub async fn authenticate(&self, role_guard: Secret<Role>) -> AccessStatus {
        // TODO Check if there is need for constant-time comparison
        let check_lease = self.check_lease().await;
        let check_role = self.check_role(role_guard).await;

        if check_lease == AccessStatus::Granted && check_role == AccessStatus::Granted {
            AccessStatus::Granted
        }else if check_lease == AccessStatus::Expired {
            AccessStatus::Expired
        }else if check_role == AccessStatus::Denied && check_lease == AccessStatus::Denied {
            AccessStatus::Revoked
        } else if check_role == AccessStatus::Rejected {
            AccessStatus::Rejected
        }else {
            AccessStatus::Denied
        }
    }

    async fn check_lease(&self) -> AccessStatus {    
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

    async fn check_role(&self, role_guard: Secret<Role>) -> AccessStatus {
        // TODO Check if there is need for constant-time comparison
        let role = self.role.expose_secret();
        
        if role == &Role::Unspecified {
            AccessStatus::Denied
        }else if role == role_guard.expose_secret() {
            AccessStatus::Granted
        }else {
            AccessStatus::Rejected
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Token {
    key: Option<SecretString>,
    contents: TokenContents,
}

impl secrecy::DebugSecret for Token {}

impl Token {
    pub async fn new() -> Self {
        Self {
            key: None,
            contents: TokenContents::new().await,
        }
    }

    pub async fn key(&mut self, value: SecretString) -> &mut Self {
        self.key = Some(value);

        self
    }

    pub async fn contents(&mut self, value: TokenContents) -> &mut Self {
        self.contents = value;

        self
    }

    async fn key_check(user_key: Option<&SecretString>) -> Result<SecretString> {
        let key;
        
        // Constant time comparison is not important as the nonce and key length are constant in a XChaCha20Poly1305 algorithm
        if let Some(secret_key) = user_key {
            if secret_key.expose_secret().len() < 32_usize { //TODO 
                return Err(anyhow::Error::new(AeadErrors::KeyTooShort))
            }else if secret_key.expose_secret().len() > 32_usize {
                return Err(anyhow::Error::new(AeadErrors::KeyTooLong))
            }else {
                key = secret_key;
            }
        }else { 
            return Err(anyhow::Error::new(AeadErrors::KeyTooShort)) 
        }

        Ok(key.to_owned())
    }


    async fn nonce_check(secret_nonce: &SecretString) -> Result<SecretString> {
        let nonce;

        if secret_nonce.expose_secret().len() < 24_usize {
            return Err(anyhow::Error::new(AeadErrors::NonceTooShort))
        }else if secret_nonce.expose_secret().len() > 24_usize {
            return Err(anyhow::Error::new(AeadErrors::NonceTooLong))
        }else {
            nonce = secret_nonce;
        }

        Ok(nonce.to_owned())
    }

    pub async fn encrypt(&mut self) -> Result<(SecretString, TokenContents)> {
        let checked_key = Token::key_check(self.key.as_ref()).await?;
        let checked_nonce = Token::nonce_check(&self.contents.proof).await?;

        let key = GenericArray::clone_from_slice(checked_key.expose_secret().as_bytes()); //32 bytes
        let nonce = GenericArray::from_slice(checked_nonce.expose_secret().as_bytes()); //24 bytes unique per message

        let aead = XChaCha20Poly1305::new(key);
        let ciphertext = aead.encrypt(
            nonce,
            bincode::serialize::<TokenContents>(&self.contents)?.as_ref(),
        );

        match ciphertext {
            Ok(inner) => {
                let mut data = TokenContents::new().await;
                data.swap(&self.contents).await;
                data.build().await;

                Ok((SecretString::new(BASE64URL_NOPAD.encode(&inner)), data))
            },
            Err(_) => Err(anyhow::Error::new(AeadErrors::EncryptionFailed)),
        }
    }

    pub async fn decrypt(&self, ciphertext: SecretString, nonce_stored: &SecretString) -> Result<TokenContents> {
        let checked_key = Token::key_check(self.key.as_ref()).await?;
        let checked_nonce = Token::nonce_check(nonce_stored).await?;

        let key = GenericArray::clone_from_slice(checked_key.expose_secret().as_bytes()); //32 bytes
        let nonce = GenericArray::from_slice(checked_nonce.expose_secret().as_bytes()); //24 bytes unique per message
        let aead = XChaCha20Poly1305::new(key);
        let plaintext = aead.decrypt(nonce, BASE64URL_NOPAD.decode(ciphertext.expose_secret().as_bytes())?.as_ref());

        match plaintext {
            Ok(inner) => Ok(bincode::deserialize::<TokenContents>(&inner)?),
            Err(_) => Err(anyhow::Error::new(AeadErrors::DecryptionFailed)),
        }
    }
}

#[derive(Debug)]
enum AeadErrors {
    EncryptionFailed,
    DecryptionFailed,
    KeyTooShort,
    KeyTooLong,
    NonceTooShort,
    NonceTooLong,
}

impl std::fmt::Display for AeadErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AeadErrors::EncryptionFailed => write!(f, "{:?}", AeadErrors::EncryptionFailed),
            AeadErrors::DecryptionFailed => write!(f, "{:?}", AeadErrors::DecryptionFailed),
            AeadErrors::KeyTooShort => write!(f, "{:?}", AeadErrors::KeyTooShort),
            AeadErrors::KeyTooLong => write!(f, "{:?}", AeadErrors::KeyTooLong),
            AeadErrors::NonceTooLong => write!(f, "{:?}", AeadErrors::NonceTooLong),
            AeadErrors::NonceTooShort => write!(f, "{:?}", AeadErrors::NonceTooShort),
        }
    }
}

impl std::error::Error for AeadErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AeadErrors::EncryptionFailed => Some(&AeadErrors::EncryptionFailed),
            AeadErrors::DecryptionFailed => Some(&AeadErrors::DecryptionFailed),
            AeadErrors::KeyTooShort => Some(&AeadErrors::KeyTooShort),
            AeadErrors::KeyTooLong => Some(&AeadErrors::KeyTooLong),
            AeadErrors::NonceTooShort => Some(&AeadErrors::NonceTooShort),
            AeadErrors::NonceTooLong => Some(&AeadErrors::NonceTooLong),
        }
    }
}
