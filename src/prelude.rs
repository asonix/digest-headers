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
    fn as_digest(self, sha_size: ShaSize) -> Result<(Self, Digest), Self::Error>;
}

/// The `IntoDigest` trait provides a method to convert the current type into a Digest.
pub trait IntoDigest {
    /// The `Item` type defines any extra type that may not be consumed in the creation of the
    /// `Digest`, it may be reasonalbe to make this `()`.
    type Item;
    /// The `Error` type defines any error that may occur in the creation of the `Digest`.
    type Error;

    fn into_digest(self, sha_size: ShaSize) -> Result<(Self::Item, Digest), Self::Error>;
}

/// The `WithDigest` trait provides a method to add a `Digest` header to a given type.
pub trait WithDigest: AsDigest {
    /// Add a `Digest` to the given type.
    fn with_digest(self, sha_size: ShaSize) -> Result<Self, Self::Error>;
}
