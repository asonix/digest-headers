# Digest Headers
_A library to aid in the creation and verification of Digest Headers, Sha Digests of HTTP Request
Bodies_

## Current Status
### Supported
 - Creation of Digest Header strings
 - Verification of Digest Header strings
 - Adding Digest Headers to Hyper Requests (with the `use_hyper` feature).

### Not Supported
 - Generic Verification Traits for servers (This may or may not end up being supported. It's simple
   enough to implement verification without the aid of fancy traits, and the implementation details
   for each server kind are too different to fit nicely into a trait).
 - Adding Digest Headers to Reqwest Requests (with the `use_reqwest` feature).

There are currently no examples, although there are tests for all added features.

## Contributing
Please be aware that all code contributed to this project will be licensed under the GPL version 3.

### License
Digest Headers is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

Digest Headers is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. This file is part of Digest Headers

You should have received a copy of the GNU General Public License along with Digest Headers If not, see http://www.gnu.org/licenses/.
