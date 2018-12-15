//! Error and result types.
//!
//! Configuration errors return specific information to help
//! the developer to build correct code.  All runtime errors
//! return the generic empty `Error` struct, because granular
//! error reporting in cryptographic libraries can be fraught.

use std::fmt;

/// A runtime error in the signal protocol.
#[derive(Clone, PartialEq, Eq)]
pub struct Error;

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "crypto error in Signal protocol")
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

/// A helful alias for a `Result` with our `Error`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that arise from parameter configuration.
#[derive(Clone, PartialEq, Eq)]
pub enum ParameterError {
    /// The curve specified is unsupported by this implementation.
    UnsupportedCurve,
    /// The supplied info value is not valid ASCII.
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

/// Errors that arise during parameter configuration when using
/// the operating system's random number generator.
pub enum WithOsRngError {
    /// A parameter configuration error.
    Parameter(ParameterError),
    /// An error getting the OS random number generator.
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
