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

use std::io::Read;

use digest_headers::Digest;
use rocket::data::{self, Data, FromData};
use rocket::request::{self, FromRequest, Request};
use rocket::Outcome;
use rocket::http::Status;

/// Verify the presence and format of a Digest header.
struct DigestHeader(Digest);

impl DigestHeader {
    pub fn new(digest: Digest) -> Self {
        DigestHeader(digest)
    }

    pub fn into_inner(self) -> Digest {
        self.0
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for DigestHeader {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<DigestHeader, ()> {
        let res = request.headers().get_one("Digest");

        if let Some(res) = res {
            if let Ok(digest) = res.parse::<Digest>() {
                return Outcome::Success(DigestHeader::new(digest));
            }
        }

        Outcome::Failure((Status::BadRequest, ()))
    }
}

/// Verify the presence of a Content-Length header.
struct ContentLengthHeader(usize);

impl ContentLengthHeader {
    pub fn new(content_length: usize) -> Self {
        ContentLengthHeader(content_length)
    }

    pub fn content_length(&self) -> usize {
        self.0
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for ContentLengthHeader {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<ContentLengthHeader, ()> {
        let res = request.headers().get_one("Content-Length");

        if let Some(res) = res {
            if let Ok(content_length) = res.parse::<usize>() {
                return Outcome::Success(ContentLengthHeader::new(content_length));
            }
        }

        Outcome::Failure((Status::BadRequest, ()))
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
///     let post = data.into_inner();
///     ...
/// }
/// ```
struct DigestVerifiedBody(Vec<u8>);

impl DigestVerifiedBody {
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl FromData for DigestVerifiedBody {
    type Error = ();

    fn from_data(req: &Request, data: Data) -> data::Outcome<Self, ()> {
        let digest = match req.guard::<DigestHeader>() {
            Outcome::Success(dh) => dh.into_inner(),
            Outcome::Failure(fail) => return Outcome::Failure(fail),
            Outcome::Forward(_) => return Outcome::Forward(data),
        };

        let content_length = match req.guard::<ContentLengthHeader>() {
            Outcome::Success(clh) => clh.content_length(),
            Outcome::Failure(fail) => return Outcome::Failure(fail),
            Outcome::Forward(_) => return Outcome::Forward(data),
        };

        // Ensure request is less than 2 MB. This is still likely way too large
        if content_length > 1024 * 1024 * 2 {
            return Outcome::Failure((Status::BadRequest, ()));
        }

        let mut body = vec![0u8; content_length];

        // Only read as much data as we expect to avoid DOS
        if let Err(_) = data.open().read_exact(&mut body) {
            return Outcome::Failure((Status::InternalServerError, ()));
        }

        let body_digest = Digest::new(&body, digest.sha_size());

        if digest != body_digest {
            return Outcome::Failure((Status::BadRequest, ()));
        }

        Outcome::Success(DigestVerifiedBody(body))
    }
}

#[post("/", data = "<data>")]
fn index(data: DigestVerifiedBody) -> String {
    if let Ok(data) = std::str::from_utf8(&data.into_inner()) {
        println!("Received {}", data);
        format!("Verified!: {}", data)
    } else {
        format!("Failed to verify data")
    }
}

fn main() {
    rocket::ignite().mount("/", routes![index]).launch();
}
