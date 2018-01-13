# Digest Headers
_A library to aid in the creation and verification of Digest Headers, Sha Digests of HTTP Request
Bodies_

## Current Status
### Supported
 - Creation of Digest Header strings
 - Verification of Digest Header strings
 - Adding Digest Headers to Hyper Requests (with the `use_hyper` feature).
 - Digest and Content Length Header request guards for Rocket (with the `use_rocket` feature).

## Examples
### Status
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
