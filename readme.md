# jsonweb

> **Note** this crate itself has not been audited. Some of the underlying [RustCrypto](https://github.com/RustCrypto)
> implementations may have been audited.

Models and traits for working with JSON Web Tokens (JWT), Algorithms (JWA), and Keys (JWK) with a focus on ease of use and
simplicity.

## Usage

I currently have no intentions to publish this to crates.io, so for now if you want to use this you can add as a git
dependency using:

```toml
jsonweb = { git = "https://github.com/Jumpdrive-dev/jsonweb", tag = "1.0.0" }
```

## Features and plans

- [x] Simple JWT signing and verifying.
- [x] Implementation of common algorithms:
  - [x] HS256
  - [x] RS256
  - [x] ES256
  - [x] None
- [ ] JWKs