# Dyno

[![CI 🏗](https://github.com/RealImage/dyno/actions/workflows/ci.yml/badge.svg)](https://github.com/RealImage/dyno/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/RealImage/dyno.svg)](https://pkg.go.dev/github.com/RealImage/dyno)

Encrypt and decrypt DynamoDB primary key attribute values.
You can either use AWS KMS (don't manage keys; expensive) or AES with
your choice of password.

Use it to send encrypted last evaluated key values that clients can use
as cursors to paginate through DynamoDB results.

## License

Dyno is available under the terms of the MIT license.

Qube Cinema © 2023
