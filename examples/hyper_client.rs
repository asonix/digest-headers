/* This file is part of Digest Headers
 *
 * Digest Headers is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Digest Headers is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Digest Headers  If not, see <http://www.gnu.org/licenses/>.
 */

extern crate digest_headers;
extern crate futures;
extern crate hyper;
extern crate tokio_core;

use digest_headers::{Digest, ShaSize};
use digest_headers::use_hyper::DigestHeader;
use futures::{Future, Stream};
use hyper::{Client, Method, Request};
use hyper::header::{ContentLength, ContentType};
use tokio_core::reactor::Core;

fn main() {
    let mut core = Core::new().unwrap();
    let client = Client::new(&core.handle());

    let uri = "http://localhost:8000".parse().unwrap();
    let json = r#"{"Library":"Hyper"}"#;

    let mut req = Request::new(Method::Post, uri);

    req.headers_mut().set(ContentType::json());
    req.headers_mut().set(ContentLength(json.len() as u64));
    req.headers_mut().set(DigestHeader(Digest::new(
        json.as_bytes(),
        ShaSize::TwoFiftySix,
    )));
    req.set_body(json);

    let post = client
        .request(req)
        .and_then(|res| {
            println!("POST: {}", res.status());

            res.body().concat2()
        })
        .and_then(|body| {
            if let Ok(body) = String::from_utf8(body.to_vec()) {
                println!("Received: {}", body);
            } else {
                println!("Garbage response body");
            }

            Ok(())
        });

    core.run(post).unwrap();
}
