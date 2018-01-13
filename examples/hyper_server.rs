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

extern crate hyper;
extern crate futures;
extern crate digest_headers;

use digest_headers::use_hyper::DigestHeader;
use futures::{Future, Stream};
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

fn main() {
    let addr = "127.0.0.1:8000".parse().unwrap();
    let server = Http::new()
        .bind(&addr, || Ok(Responder))
        .unwrap();
    server.run().unwrap();
}
