use failure::Fail;

    /// `SGError` is the main error type
#[derive(Fail, Debug)]
pub enum SGError {
        /// Branca Error type `branca::errors::Error`
    #[fail(display = "{}", _0)]
    BrancaError(#[cause] branca::errors::Error),
        /// Sled errors for `Pagecache`
    #[fail(display = "{}", _0)]
    SledError(#[cause] sled::Error),
        /// Bincode error handling for `bincode::Error` errors
    #[fail(display = "{}", _0)]
    BincodeError(#[cause] bincode::Error),
        /// String error handling for `string::FromUtf8Error` errors
    #[fail(display = "{}", _0)]
    StringUtf8Error(#[cause] std::string::FromUtf8Error),
        /// String error handling for `num::TryFromIntError` errors
    #[fail(display = "{}", _0)]
    TryFromIntError(#[cause] std::num::TryFromIntError),
        /// String error handling for `serde_json::error::Error` errors
    #[fail(display = "{}", _0)]
    SerdeJsonError(#[cause] serde_json::error::Error),
}

impl std::convert::From<branca::errors::Error> for SGError {
    fn from(error: branca::errors::Error) -> Self {
        SGError::BrancaError(error)
    }
}

impl std::convert::From<sled::Error> for SGError {
    fn from(error: sled::Error) -> Self {
        SGError::SledError(error)
    }
}

impl std::convert::From<bincode::Error> for SGError {
    fn from(error: bincode::Error) -> Self {
        SGError::BincodeError(error)
    }
}

impl std::convert::From<std::string::FromUtf8Error> for SGError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        SGError::StringUtf8Error(error)
    }
}

impl std::convert::From<std::num::TryFromIntError> for SGError {
    fn from(error: std::num::TryFromIntError) -> Self {
        SGError::TryFromIntError(error)
    }
}

impl std::convert::From<serde_json::error::Error> for SGError {
    fn from(error: serde_json::error::Error) -> Self {
        SGError::SerdeJsonError(error)
    }
}