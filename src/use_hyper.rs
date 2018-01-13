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

//! The `use_hyper` module provides useful Types and Traits for interacting with `Hyper` with
//! `Digest`s.

use futures::{Future, Stream};
use hyper::{Body, Chunk, Request};
use hyper::header::{Formatter, Header, Raw};
use hyper::error::{Error as HyperError, Result as HyperResult};

use std::error::Error as StdError;
use std::fmt;
use std::str::from_utf8;

use {Digest, ShaSize};
use prelude::*;

/// The Error type for using Digests with Hyper.
#[derive(Debug)]
pub enum Error {
    /// Hyper had an error
    Hyper(HyperError),
    /// There was no body in the Request.
    NoBody,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Hyper(ref hyper_error) => write!(f, "Hyper: {}", hyper_error),
            Error::NoBody => write!(f, "No body was found in the Request."),
        }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Hyper(ref hyper_error) => hyper_error.description(),
            Error::NoBody => "No body was found in the Request",
        }
    }
}

impl From<HyperError> for Error {
    fn from(e: HyperError) -> Self {
        Error::Hyper(e)
    }
}

/// The `DigestHeader` is used to create and verify Digests on Hyper requests.
///
/// # Example of Creation
///
/// ```rust
/// # extern crate digest_headers;
/// # extern crate hyper;
/// #
/// # use digest_headers::{Digest, ShaSize};
/// # use digest_headers::prelude::*;
/// # use digest_headers::use_hyper::{Error, DigestHeader};
/// # use hyper::{Method, Request};
/// #
/// # fn main() {
/// #     run().unwrap();
/// # }
/// #
/// # fn run() -> Result<(), Error> {
/// let uri = "http://example.com".parse().unwrap();
/// let json = r#"{"Library":"Hyper"}"#;
///
/// let mut req: Request = Request::new(Method::Post, uri);
/// req.headers_mut().set(DigestHeader(Digest::new(json.as_bytes(), ShaSize::TwoFiftySix)));
/// req.set_body(json);
/// # Ok(())
/// # }
/// ```
///
/// # Example of Verification
/// ```rust
/// # extern crate digest_headers;
/// # extern crate futures;
/// # extern crate hyper;
/// #
/// # use digest_headers::{Digest, ShaSize};
/// # use digest_headers::prelude::*;
/// # use digest_headers::use_hyper::{Error, DigestHeader};
/// # use futures::{Future, Stream};
/// # use hyper::{Method, Request};
/// #
/// fn handle_request(mut req: Request) {
///     let digest_header = req
///         .headers_mut()
///         .remove::<DigestHeader>()
///         .unwrap();
///
///     let digest_header = digest_header.0;
///
///     // Don't actually use `.wait()` in real code.
///     req.body()
///         .concat2()
///         .and_then(|body| {
///             let digest = Digest::new(&body, digest_header.sha_size());
///
///             assert_eq!(digest_header, digest);
///             Ok(())
///         })
///         .wait()
///         .unwrap();
/// }
/// #
/// # fn main() {
/// #     let uri = "http://example.com".parse().unwrap();
/// #     let json = r#"{"Library":"Hyper"}"#;
/// #
/// #     let mut req: Request = Request::new(Method::Post, uri);
/// #     req.headers_mut().set(DigestHeader(Digest::new(json.as_bytes(), ShaSize::TwoFiftySix)));
/// #     req.set_body(json);
/// #     handle_request(req);
/// # }
/// ```
#[derive(Clone)]
pub struct DigestHeader(pub Digest);

impl DigestHeader {
    pub fn into_digest(self) -> Digest {
        self.0
    }

    pub fn digest_string(&self) -> String {
        self.0.as_string()
    }
}

impl Header for DigestHeader {
    fn header_name() -> &'static str {
        "Digest"
    }

    fn parse_header(raw: &Raw) -> HyperResult<Self> {
        if let Some(one) = raw.one() {
            if let Ok(s) = from_utf8(one) {
                let digest = s.parse::<Digest>().map_err(|_| HyperError::Header)?;

                return Ok(DigestHeader(digest));
            }
        }

        Err(HyperError::Header)
    }

    fn fmt_header(&self, f: &mut Formatter) -> fmt::Result {
        f.fmt_line(&self.0)
    }
}

impl IntoDigest for Body {
    type Item = Chunk;
    type Error = Error;

    fn into_digest(self, sha_size: ShaSize) -> Result<(Self::Item, Digest), Self::Error> {
        let full_body = self.concat2().wait()?;

        let digest = Digest::new(&full_body, sha_size);

        Ok((full_body, digest))
    }
}

impl AsDigest for Request<Body> {
    type Error = Error;

    /// We need to consume the body Stream in order to access it, but we can set the body again
    /// after we've concatenated the whole body together, since getting a Digest is
    /// non-destructive.
    ///
    /// Do not call this method from the context of an asyncronous executor unless you are certain
    /// that the body in the Request is a single item. It will block waiting for all items.
    fn as_digest(self, sha_size: ShaSize) -> Result<(Self, Digest), Self::Error> {
        let (method, uri, http_version, headers, body) = self.deconstruct();

        let (body, digest) = body.into_digest(sha_size)?;

        let mut req = Request::new(method, uri);

        *req.headers_mut() = headers;

        req.set_version(http_version);
        req.set_body(body);

        Ok((req, digest))
    }
}

impl WithDigest for Request<Body> {
    /// We need to consume the body Stream in order to access it, but we can set the body again
    /// after we've concatenated the whole body together, since getting a Digest is
    /// non-destructive.
    ///
    /// Do not call this method from the context of an asyncronous executor unless you are certain
    /// that the body in the Request is a single item. It will block waiting for all items.
    fn with_digest(self, sha_size: ShaSize) -> Result<Self, Self::Error> {
        let (mut req, digest) = self.as_digest(sha_size)?;

        req.headers_mut().set(DigestHeader(digest));

        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use futures::{Future, Stream};
    use hyper::{Body, Method, Request};
    use hyper::header::{ContentLength, ContentType};
    use tokio_core::reactor::Core;

    use super::DigestHeader;
    use {Digest, ShaSize};
    use prelude::*;

    #[test]
    fn add_digest_to_request_256() {
        add_digest_to_request(ShaSize::TwoFiftySix);
    }

    #[test]
    fn add_digest_to_request_384() {
        add_digest_to_request(ShaSize::ThreeEightyFour);
    }

    #[test]
    fn add_digest_to_request_512() {
        add_digest_to_request(ShaSize::FiveTwelve);
    }

    fn add_digest_to_request(sha_size: ShaSize) {
        let mut core = Core::new().unwrap();
        let uri = "http://example.com".parse().unwrap();
        let json = r#"{"Library":"Hyper"}"#;

        let mut req: Request<Body> = Request::new(Method::Post, uri);

        req.set_body(json);
        req.headers_mut().set(ContentType::json());
        req.headers_mut().set(ContentLength(json.len() as u64));

        let req = req.with_digest(sha_size);

        assert!(req.is_ok());

        // Stop Building request, start handling request

        let mut req = req.unwrap();

        let digest_header = req.headers_mut().remove::<DigestHeader>();

        assert!(digest_header.is_some());

        let digest_header = digest_header.unwrap();
        let digest_header = digest_header.into_digest();

        // Create a Future that will verify the digest upon reception
        let fut = req.body().concat2().and_then(|body| {
            let digest = Digest::new(&body, digest_header.sha_size());

            assert_eq!(digest_header, digest);
            Ok(())
        });

        core.run(fut).unwrap();
    }
}
