/* This file is part of HTTP Signatures
 *
 * HTTP Signatures is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * HTTP Signatures is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with HTTP Signatures  If not, see <http://www.gnu.org/licenses/>.
 */

//! This file defines the types and logic for interacting with Digests from Rocket.
//!
//! Of primary importance is the `DigestHeader` request guard, which can be used directly in a
//! route, or can be used inside another request guard.
//!
//! Also defined in this file is the `ContentLengthHeader` request guard, and the `Error` type that
//! these guards produce.
//!
//! For a full example of how these types can be used, see the
//! [rocket example](https://github.com/asonix/digest-headers/blob/master/examples/rocket.rs) on
//! github.

use std::error::Error as StdError;
use std::fmt;

use rocket::request::{self, FromRequest, Request};
use rocket::Outcome;
use rocket::http::Status;

use Digest;
use error::Error as DigestError;

/// The error type for Rocket-related Digest logic
///
/// This type is used in the implementations of `rocket::request::FromRequest` for `DigestHeader`
/// and `ContentLengthHeader`.
#[derive(Clone, Debug)]
pub enum Error {
    /// An error creating a Digest
    Digest(DigestError),
    /// An error parsing a header
    Header(&'static str),
}

impl Error {
    /// A function that can convert this error type into a Rocket Failure tuple.
    ///
    /// For both cases, the associated status is BadRequest.
    pub fn as_rocket_failure(self) -> (Status, Self) {
        match self {
            Error::Digest(digest) => (Status::BadRequest, Error::Digest(digest)),
            Error::Header(which) => (Status::BadRequest, Error::Header(which)),
        }
    }
}

impl From<DigestError> for Error {
    fn from(e: DigestError) -> Self {
        Error::Digest(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Digest(ref e) => write!(f, "Digest: {}", e),
            _ => write!(f, "{}", self.description()),
        }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Digest(ref e) => e.description(),
            Error::Header(_) => "Expected exactly one header",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Error::Digest(ref e) => Some(e),
            _ => None,
        }
    }
}

/// Verify the presence and format of a Digest header.
///
/// This can be used as a request guard
///
/// ```rust
/// # extern crate digest_headers;
/// #
/// # use digest_headers::{Digest, ShaSize};
/// # use digest_headers::use_rocket::DigestHeader;
/// #
/// fn index(data: DigestHeader) -> String {
///     let digest = data.0;
///
///     format!("Digest was {}", digest)
/// }
/// #
/// # fn main() {
/// #     index(DigestHeader(Digest::new(b"Some text", ShaSize::TwoFiftySix)));
/// # }
/// ```
pub struct DigestHeader(pub Digest);

impl DigestHeader {
    pub fn new(digest: Digest) -> Self {
        DigestHeader(digest)
    }

    pub fn into_inner(self) -> Digest {
        self.0
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for DigestHeader {
    type Error = Error;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<DigestHeader, Self::Error> {
        let res = request
            .headers()
            .get_one("Digest")
            .ok_or(Error::Header("Digest"))
            .and_then(|raw_header| {
                raw_header.parse::<Digest>().map_err(Error::from)
            })
            .map(DigestHeader);

        match res {
            Ok(success) => Outcome::Success(success),
            Err(error) => Outcome::Failure(error.as_rocket_failure()),
        }
    }
}

/// Verify the presence of a Content-Length header.
///
/// This can be used as a request guard
///
/// ```rust
/// # extern crate digest_headers;
/// #
/// # use digest_headers::use_rocket::ContentLengthHeader;
/// #
/// fn index(data: ContentLengthHeader) -> String {
///     let content_length = data.0;
///
///     format!("Content-Length was {}", content_length)
/// }
/// #
/// # fn main() {
/// #     index(ContentLengthHeader(5));
/// # }
/// ```
pub struct ContentLengthHeader(pub usize);

impl<'a, 'r> FromRequest<'a, 'r> for ContentLengthHeader {
    type Error = Error;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<ContentLengthHeader, Self::Error> {
        let res = request
            .headers()
            .get_one("Content-Length")
            .ok_or(Error::Header("Content-Length"))
            .and_then(|raw_header| {
                raw_header.parse::<usize>().map_err(|_| Error::Header("Content-Length"))
            })
            .map(ContentLengthHeader);

        match res {
            Ok(success) => Outcome::Success(success),
            Err(error) => Outcome::Failure(error.as_rocket_failure()),
        }
    }
}
