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

#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate digest_headers;
extern crate rocket;

use std::error::Error as StdError;
use std::fmt;
use std::io::Read;

use digest_headers::Digest;
use digest_headers::use_rocket::{Error as DigestError, ContentLengthHeader, DigestHeader};
use rocket::data::{self, Data, FromData};
use rocket::request::Request;
use rocket::Outcome;
use rocket::http::Status;

#[derive(Clone, Debug)]
enum Error {
    Digest(DigestError),
    RequestTooBig,
    ReadFailed,
    DigestMismatch,
}

impl From<DigestError> for Error {
    fn from(e: DigestError) -> Self {
        Error::Digest(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Digest(ref de) => write!(f, "DigestError {}", de),
            _ => write!(f, "{}", self.description()),
        }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Digest(ref e) => e.description(),
            Error::RequestTooBig => "Request too big to process",
            Error::ReadFailed => "Unable to read request body",
            Error::DigestMismatch => "The provided digest does not match the body",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Error::Digest(ref e) => Some(e),
            _ => None,
        }
    }
}

/// Create a basic type that can be converted from a Body.
///
/// In a real application, you might do something like
///
/// ```rust
/// DigestVerified<T>(T)
/// where
///     T: serde::de::DeserializeOwned;
/// ```
///
/// so in your route you could do something like
///
/// ```rust
/// #[post("/", data = "<data>")]
/// fn index(data: DigestVerified<Post>) -> YourResponse {
///     let post = data.0;
///     ...
/// }
/// ```
struct DigestVerifiedBody<T>(pub T);

impl FromData for DigestVerifiedBody<Vec<u8>> {
    type Error = Error;

    fn from_data(req: &Request, data: Data) -> data::Outcome<Self, Self::Error> {
        let digest = match req.guard::<DigestHeader>() {
            Outcome::Success(dh) => dh.0,
            Outcome::Failure((status, error)) => return Outcome::Failure((status, error.into())),
            Outcome::Forward(_) => return Outcome::Forward(data),
        };

        println!("Provided Digest: {:?}", digest);

        let content_length = match req.guard::<ContentLengthHeader>() {
            Outcome::Success(clh) => clh.0,
            Outcome::Failure((status, error)) => return Outcome::Failure((status, error.into())),
            Outcome::Forward(_) => return Outcome::Forward(data),
        };

        println!("Content Length: {}", content_length);

        // Ensure request is less than 2 MB. This is still likely way too large
        if content_length > 1024 * 1024 * 2 {
            return Outcome::Failure((Status::BadRequest, Error::RequestTooBig));
        }

        let mut body = vec![0u8; content_length];

        // Only read as much data as we expect to avoid DOS
        if let Err(_) = data.open().read_exact(&mut body) {
            return Outcome::Failure((Status::InternalServerError, Error::ReadFailed));
        }

        let body_digest = Digest::new(&body, digest.sha_size());

        if digest != body_digest {
            return Outcome::Failure((Status::BadRequest, Error::DigestMismatch));
        }

        Outcome::Success(DigestVerifiedBody(body))
    }
}

#[post("/", data = "<data>")]
fn index(data: DigestVerifiedBody<Vec<u8>>) -> String {
    if let Ok(data) = std::str::from_utf8(&data.0) {
        println!("Received {}", data);
        format!("Verified!: {}", data)
    } else {
        format!("Failed to verify data")
    }
}

fn main() {
    rocket::ignite().mount("/", routes![index]).launch();
}
