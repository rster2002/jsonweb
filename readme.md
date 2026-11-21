# jsonweb

> **Note** this crate itself has not been audited. Some of the underlying [RustCrypto](https://github.com/RustCrypto)
> implementations may have been audited.

Models and traits for working with JSON Web Tokens (JWT), Algorithms (JWA), and Keys (JWK) with a focus on ease of use and
simplicity.

## Features and plans

This is a list of features and plans for the crate.

- [x] Simple JWT signing and verifying.
- [x] Implementation of common algorithms:
  - [x] HS256
  - [x] RS256
  - [x] ES256
  - [x] None
- [ ] JWKs