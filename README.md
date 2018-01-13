# Digest Headers
_A library to aid in the creation and verification of Digest Headers, Sha Digests of HTTP Request
Bodies_

## Getting started
### Building requests with Hyper
```rust
use digest_headers::Digest;
use digest_headers::use_hyper::DigestHeader;

let mut req = Request::new(Method::Post, uri);

req.headers_mut().set(ContentType::json());
req.headers_mut().set(ContentLength(json.len() as u64));
req.headers_mut().set(DigestHeader(Digest::new(
    json.as_bytes(),
    ShaSize::TwoFiftySix,
)));
req.set_body(json);
```
### Handling requests with Hyper
```rust
use digest_headers::use_hyper::DigestHeader;
use futures::{Future, IntoFuture, Stream};
use hyper::server::{Http, Request, Response, Service};

struct Responder;

impl Service for Responder {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;

    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, mut req: Self::Request) -> Self::Future {
        let digest = req
            .headers_mut()
            .remove::<DigestHeader>()
            .ok_or(hyper::Error::Header);

        let fut = req
            .body()
            .concat2()
            .join(digest)
            .and_then(|(body, digest)| {
                if digest.0.verify(&body).is_ok() {
                    println!("Verified!");
                    Ok(Response::new().with_body(body))
                } else {
                    println!("Bad Request!");
                    Err(hyper::Error::Header)
                }
            });

        Box::new(fut)
    }
}
```
### Handling requests with Rocket
```rust
use digest_headers::use_rocket::DigestHeader;
use rocket::data::{self, FromData};

struct DigestVerifiedBody<T>(pub T);

impl FromData for DigestVerifiedBody<Vec<u8>> {
    type Error = ();

    fn from_data(req: &Request, data: Data) -> data::Outcome<Self, Self::Error> {
        let digest = match req.guard::<DigestHeader>() {
            Outcome::Success(dh) => dh.0,
            Outcome::Failure((status, _)) => return Outcome::Failure((status, ())),
            Outcome::Forward(_) => return Outcome::Forward(data),
        };

        let mut body = Vec::new();

        // This is a really obvious Denial-of-service attack.
        // Please see the rocket example for a better way to do this.
        // https://github.com/asonix/digest-headers/blob/master/examples/rocket.rs
        if let Err(_) = data.open().read_to_end(&mut body) {
            return Outcome::Failure((Status::InternalServerError, ()));
        }

        if digest.verify(&body).is_err() {
            return Outcome::Failure((Status::BadRequest, ()));
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
```

## What this library supports
 - Creation of Digest Header strings
 - Verification of Digest Header strings
 - Adding Digest Headers to Hyper Requests (with the `use_hyper` feature).
 - Digest and Content Length Header request guards for Rocket (with the `use_rocket` feature).

## Examples
 - Hyper Client example, very short and sweet
 - Rocket Server Example. This one is more in-depth. It implements `rocket::request::FromRequest`
   for two custom structs for the `Digest` and `ContentLength` headers, and implements `FromData`
   for a simple wrapper around a `Vec<u8>`. See the example for the full implementation.

### Notes
 - The Hyper Client example is configured to send POST request to the Rocket Server example.
 - When running the examples, remember to pass the `--all-features` flag to `cargo run`

## Contributing
Please be aware that all code contributed to this project will be licensed under the GPL version 3.

### License
Digest Headers is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

Digest Headers is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. This file is part of Digest Headers

You should have received a copy of the GNU General Public License along with Digest Headers If not, see http://www.gnu.org/licenses/.
