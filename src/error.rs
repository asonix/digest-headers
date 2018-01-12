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

//! This module defines the Error type for interacting with Digests.
//!
//! Errors don't happen when creating new digests, only when verifying.

use std::error::Error as StdError;
use std::fmt;

/// The Error type
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// There was an error parsing a ShaSize
    ParseShaSize,
    /// There was an error parsing a Digest
    ParseDigest,
    /// The digest doesn't match
    InvalidDigest,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            Error::ParseShaSize => "Failed to parse ShaSize",
            Error::ParseDigest => "Failed to parse Digest",
            Error::InvalidDigest => "Digest does not match Body",
        };

        write!(f, "{}", s)
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::ParseShaSize => "Failed to parse ShaSize",
            Error::ParseDigest => "Failed to parse Digest",
            Error::InvalidDigest => "Digest does not match Body",
        }
    }
}
