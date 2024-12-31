# Dyno

[![CI 🏗](https://github.com/RealImage/dyno/actions/workflows/ci.yml/badge.svg)](https://github.com/RealImage/dyno/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/RealImage/dyno.svg)](https://pkg.go.dev/github.com/RealImage/dyno)

Encrypt and decrypt DynamoDB primary key attribute values.
You can either use AWS KMS (you don't manage keys, but its expensive)
or a cipher with your own key. AES-GCM and ChaCha20-Poly1305 are supported.

Use it to ecnrypt last evaluated key values from DynamoDB Query responses.
Clients can use these encrypted opaque values to paginate through queries.

## License

Dyno is available under the terms of the MIT license.

Qube Cinema © 2023, 2024
