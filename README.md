# Dyno

[![CI 🏗](https://github.com/RealImage/dyno/actions/workflows/ci.yml/badge.svg)](https://github.com/RealImage/dyno/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/RealImage/dyno.svg)](https://pkg.go.dev/github.com/RealImage/dyno)

Encrypt and decrypt DynamoDB table attribute value maps using either AWS KMS
or AES with a password. Useful for sending clients the LastEvaluatedKey from
the result of a DynamoDB Query or Scan operation, for paginating results without
leaking sensitive information.

## License

Dyno is available under the terms of the MIT license.

Qube Cinema © 2023
