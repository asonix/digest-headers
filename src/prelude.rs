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

//! The `prelude` module provides useful traits for working with Digest headers.

use super::{Digest, ShaSize};

/// The `AsDigest` trait provides a method to retrieve a `Digest` from a given type.
pub trait AsDigest: Sized {
    /// The `Error` type defines any error that may occur in the creation of the `Digest`.
    type Error;

    /// Retrieve a `Digest` from a given type, returning Self and the Digest.
    ///
    /// # An Example with Hyper
    ///
    /// ```rust
    /// # extern crate digest_headers;
    /// # extern crate hyper;
    /// #
    /// # use digest_headers::ShaSize;
    /// # use digest_headers::prelude::*;
    /// # use digest_headers::use_hyper::{Error, DigestHeader};
    /// # use hyper::{Body, Method, Request};
    /// #
    /// # fn main() {
    /// #     run().unwrap();
    /// # }
    /// #
    /// # fn run() -> Result<(), Error> {
    /// let uri = "http://example.com".parse().unwrap();
    /// let json = r#"{"Library":"Hyper"}"#;
    ///
    /// let mut req: Request<Body> = Request::new(Method::Post, uri);
    /// req.set_body(json);
    ///
    /// let (mut req, digest) = req.as_digest(ShaSize::TwoFiftySix)?;
    ///
    /// req.headers_mut().set(DigestHeader(digest));
    /// # Ok(())
    /// # }
    /// ```
    fn as_digest(self, sha_size: ShaSize) -> Result<(Self, Digest), Self::Error>;
}

/// The `IntoDigest` trait provides a method to convert the current type into a Digest.
///
/// # Implementing `IntoDigest` for a custom HTTP body
/// ```rust
/// extern crate digest_headers;
///
/// use digest_headers::{Digest, ShaSize};
/// use digest_headers::prelude::*;
///
/// enum Body {
///     One(Vec<u8>),
///     Two(Vec<u8>, Vec<u8>),
/// }
///
/// impl Body {
///     fn new(data: Vec<u8>) -> Self {
///         Body::One(data)
///     }
///
///     fn get_data(self) -> Vec<u8> {
///         match self {
///             Body::One(data) => {
///                 data
///             }
///             Body::Two(mut d1, d2) => {
///                 d1.extend(d2);
///                 d1
///             }
///         }
///     }
/// }
///
/// // This implementation is very similar to the code used when implementing `IntoDigest` for
/// // `Hyper::Body`.
/// impl IntoDigest for Body {
///     type Item = Body;
///     type Error = ();
///
///     fn into_digest(self, sha_size: ShaSize) -> Result<(Self::Item, Digest), Self::Error> {
///         let data = self.get_data();
///
///         let digest = Digest::new(&data, sha_size);
///
///         Ok((Body::new(data), digest))
///     }
/// }
/// #
/// # fn main() {
/// #     let b = Body::new(vec![1, 2, 3, 4]);
/// #     let (b, d) = b.into_digest(ShaSize::TwoFiftySix).unwrap();
/// # }
/// ```
pub trait IntoDigest {
    /// The `Item` type defines any extra type that may not be consumed in the creation of the
    /// `Digest`, it may be reasonalbe to make this `()`.
    type Item;
    /// The `Error` type defines any error that may occur in the creation of the `Digest`.
    type Error;

    /// Convert a given type into a Digest, returning any unused data as `Self::Item`
    ///
    /// This trait is not something that you'll interact with directly, but it exists as a way to
    /// help implementing `AsDigest` for types that must be destroyed to be used.
    fn into_digest(self, sha_size: ShaSize) -> Result<(Self::Item, Digest), Self::Error>;
}

/// The `WithDigest` trait provides a method to add a `Digest` header to a given type.
pub trait WithDigest: AsDigest {
    /// Add a `Digest` to the given type.
    ///
    /// # An Example with Hyper
    ///
    /// ```rust
    /// # extern crate digest_headers;
    /// # extern crate hyper;
    /// #
    /// # use digest_headers::ShaSize;
    /// # use digest_headers::prelude::*;
    /// # use digest_headers::use_hyper::{Error, DigestHeader};
    /// # use hyper::{Body, Method, Request};
    /// #
    /// # fn main() {
    /// #     run().unwrap();
    /// # }
    /// #
    /// # fn run() -> Result<(), Error> {
    /// let uri = "http://example.com".parse().unwrap();
    /// let json = r#"{"Library":"Hyper"}"#;
    ///
    /// let mut req: Request<Body> = Request::new(Method::Post, uri);
    /// req.set_body(json);
    ///
    /// let req = req.with_digest(ShaSize::TwoFiftySix)?;
    /// # let _ = req;
    /// # Ok(())
    /// # }
    /// ```
    fn with_digest(self, sha_size: ShaSize) -> Result<Self, Self::Error>;
}
