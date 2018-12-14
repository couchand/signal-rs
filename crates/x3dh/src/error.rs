use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct Error;

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "X3DH Error")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl std::error::Error for Error {}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(_: ed25519_dalek::SignatureError) -> Error { Error }
}

impl From<()> for Error {
    fn from(_: ()) -> Error { Error }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, PartialEq, Eq)]
pub enum ParameterError {
    UnsupportedCurve,
    InvalidAscii,
}

impl std::fmt::Debug for ParameterError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParameterError::UnsupportedCurve=> write!(f, "CURVE X448 is not supported."),
            ParameterError::InvalidAscii => write!(f, "INFO must be ASCII."),
        }
    }
}

impl fmt::Display for ParameterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl std::error::Error for ParameterError {}

pub enum WithOsRngError {
    Parameter(ParameterError),
    OsRng(rand::Error),
}

impl std::fmt::Debug for WithOsRngError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WithOsRngError::Parameter(p) => p.fmt(f),
            WithOsRngError::OsRng(r) => r.fmt(f),
        }
    }
}

impl fmt::Display for WithOsRngError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl std::error::Error for WithOsRngError {}

impl From<ParameterError> for WithOsRngError {
    fn from(err: ParameterError) -> WithOsRngError {
        WithOsRngError::Parameter(err)
    }
}

impl From<rand::Error> for WithOsRngError {
    fn from(err: rand::Error) -> WithOsRngError {
        WithOsRngError::OsRng(err)
    }
}
