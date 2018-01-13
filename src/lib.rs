/* This file is part of Digest Header
 *
 * Digest Header is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Digest Header is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Digest Header  If not, see <http://www.gnu.org/licenses/>.
 */

//! Digest Header, a simple library for verifying the content of HTTP Requests.
//!
//! This library doesn't offer any verification of identity, it only ensures that the content of
//! the request matches the signature in the Digest header of the request. If you want to verify
//! that a request has not been tampered with, it is best to use this library in conjunction with
//! [http signatures](https://github.com/asonix/http-signatures). This way, the Headers are signed
//! with a key, validating identity and authenticity, and the Digest header validates the body of
//! the request.

extern crate base64;
#[cfg(feature = "use_hyper")]
extern crate futures;
#[cfg(feature = "use_hyper")]
extern crate hyper;
#[cfg(feature = "use_reqwest")]
extern crate reqwest;
extern crate ring;
#[cfg(feature = "use_rocket")]
extern crate rocket;
#[cfg(feature = "use_hyper")]
extern crate tokio_core;

mod error;
pub mod prelude;

#[cfg(feature = "use_hyper")]
pub mod use_hyper;

pub use self::error::Error;

use std::fmt;
use std::str::FromStr;

/// Defines variants for the size of SHA hash.
///
/// Since this isn't being used for encryption or identification, it doesn't need to be very
/// strong. That said, it's ultimately up to the user of this library, so we provide options for
/// 256, 384, and 512.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShaSize {
    TwoFiftySix,
    ThreeEightyFour,
    FiveTwelve,
}

impl fmt::Display for ShaSize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            ShaSize::TwoFiftySix => "SHA-256",
            ShaSize::ThreeEightyFour => "SHA-384",
            ShaSize::FiveTwelve => "SHA-512",
        };

        write!(f, "{}", s)
    }
}

impl FromStr for ShaSize {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = match s {
            "SHA-256" => ShaSize::TwoFiftySix,
            "SHA-384" => ShaSize::ThreeEightyFour,
            "SHA-512" => ShaSize::FiveTwelve,
            _ => return Err(Error::ParseShaSize),
        };

        Ok(res)
    }
}

/// Defines a wrapper around an &[u8] that can be turned into a `Digest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestBody<'a>(&'a [u8]);

impl<'a> RequestBody<'a> {
    /// Creates a new `RequestBody` struct from a `&[u8]` representing a plaintext body.
    pub fn new(body: &'a [u8]) -> Self {
        RequestBody(body)
    }

    /// Consumes the `RequestBody`, producing a `Digest`.
    pub fn digest(self, sha_size: ShaSize) -> Digest {
        let size = match sha_size {
            ShaSize::TwoFiftySix => &ring::digest::SHA256,
            ShaSize::ThreeEightyFour => &ring::digest::SHA384,
            ShaSize::FiveTwelve => &ring::digest::SHA512,
        };

        let d = ring::digest::digest(size, self.0);
        let b = base64::encode(&d);

        Digest::from_base64_and_size(b, sha_size)
    }
}

/// Defines the `Digest` type.
///
/// This type can be compared to another `Digest`, or turned into a `String` for use in request
/// headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest {
    digest: String,
    size: ShaSize,
}

impl Digest {
    /// Creates a new `Digest` from a series of bytes representing a plaintext body and a
    /// `ShaSize`.
    pub fn new(body: &[u8], size: ShaSize) -> Self {
        RequestBody::new(body).digest(size)
    }

    /// Creates a new `Digest` from a base64-encoded digest `String` and a `ShaSize`.
    pub fn from_base64_and_size(digest: String, size: ShaSize) -> Self {
        Digest { digest, size }
    }

    /// Get the `ShaSize` of the current `Digest`
    pub fn sha_size(&self) -> ShaSize {
        self.size
    }

    /// Represents the `Digest` as a `String`.
    ///
    /// This can be used to produce headers for HTTP Requests.
    pub fn as_string(&self) -> String {
        format!("{}={}", self.size, self.digest)
    }
}

impl FromStr for Digest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let eq_index = s.find("=").ok_or(Error::ParseDigest)?;
        let tup = s.split_at(eq_index);
        let val = tup.1.get(1..).ok_or(Error::ParseDigest)?;

        Ok(Digest {
            digest: val.to_owned(),
            size: tup.0.parse()?,
        })
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

pub fn verify_digest(digest: &str, body: &[u8]) -> Result<(), Error> {
    let provided_digest: Digest = digest.parse()?;
    let digest = RequestBody::new(body).digest(provided_digest.size);

    if provided_digest == digest {
        Ok(())
    } else {
        Err(Error::InvalidDigest)
    }
}

#[cfg(test)]
mod tests {
    use super::{Digest, RequestBody, ShaSize};

    const D256: &'static str = "bFp1K/TT36l9YQ8frlh/cVGuWuFEy1rCUNpGwQCSEow=";
    const D384: &'static str = "wOx5d657W3O8k2P7SW18Y/Kj/Rqm02pzgFVBInHOj7hbc0IrYGVXwzid3vTH82um";
    const D512: &'static str =
        "t13li71PxOlxHbZRB3ICZxjwBkYxhellKbMEQjT2udmQRP1fzIrmT49EGy9zNdTS5/JKjxqidsIQBO3i+9DBDQ==";

    #[test]
    fn digest_256() {
        digest(D256.to_owned(), ShaSize::TwoFiftySix);
    }

    #[test]
    fn digest_384() {
        digest(D384.to_owned(), ShaSize::ThreeEightyFour);
    }

    #[test]
    fn digest_512() {
        digest(D512.to_owned(), ShaSize::FiveTwelve);
    }

    #[test]
    fn invalid_digest_256() {
        digest_ne(ShaSize::TwoFiftySix)
    }

    #[test]
    fn invalid_digest_384() {
        digest_ne(ShaSize::ThreeEightyFour)
    }

    #[test]
    fn invalid_digest_512() {
        digest_ne(ShaSize::FiveTwelve)
    }

    #[test]
    fn parse_digest_256() {
        parse_digest(format!("SHA-256={}", D256));
    }

    #[test]
    fn parse_digest_384() {
        parse_digest(format!("SHA-384={}", D384));
    }

    #[test]
    fn parse_digest_512() {
        parse_digest(format!("SHA-512={}", D512));
    }

    #[test]
    fn invalid_parse_digest() {
        parse_digest_ne("not a valid digest");
    }

    #[test]
    fn parse_sha_256() {
        parse_sha("SHA-256");
    }

    #[test]
    fn parse_sha_384() {
        parse_sha("SHA-384");
    }

    #[test]
    fn parse_sha_512() {
        parse_sha("SHA-512");
    }

    #[test]
    fn invalid_parse_sha() {
        parse_sha_ne("SHA-420");
    }

    fn digest(provided: String, sha_size: ShaSize) {
        let some_body = b"The content of a thing";
        let body = RequestBody::new(some_body);
        let digest = body.digest(sha_size);

        assert_eq!(Digest::from_base64_and_size(provided, sha_size), digest);
    }

    fn digest_ne(sha_size: ShaSize) {
        let some_body = b"The content of a thing";
        let body = RequestBody::new(some_body);
        let digest = body.digest(sha_size);

        assert_ne!(
            Digest::from_base64_and_size("not a hash".to_owned(), sha_size),
            digest
        );
    }

    fn parse_digest(digest: String) {
        let d = digest.parse::<Digest>();

        assert!(d.is_ok());
    }

    fn parse_digest_ne(digest: &str) {
        let d = digest.parse::<Digest>();

        assert!(d.is_err());
    }

    fn parse_sha(sha: &str) {
        let s = sha.parse::<ShaSize>();

        assert!(s.is_ok());
    }

    fn parse_sha_ne(sha: &str) {
        let s = sha.parse::<ShaSize>();

        assert!(s.is_err());
    }
}
