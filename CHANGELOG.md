# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [1.1.0] - 2020-07-13

### Added
* Support for passing an AWS Account alias as a query parameter instead of an ID
  number (#15)
* `decode_token` method that validates and decodes an OIDC ID Token
  and the `get_email_or_username` method to return either an email address
  or username if there is no email address (#25)
* Logging to record the user identity (obtained from the ID Token), the IP
  address of the requester and the actions taken (#25)
* New frontend state of "info" that can be used to send display messages to the
  frontend. (#25)
* Support for setting log level (#25)
* Ability to query for CloudWatch LogGroup (#25)
  
### Changed
* New async UI to conform to mozilla-aws-cli which required a broad rewrite
  of much of federated-aws-rp (#14)

### Fixed
* Need for user to log out of AWS before logging in to a new account (#14)
* Deployment on MacOS (#16)
* Bug where AWS accounts with no account alias trigger an error (#21)
* The display of error messages due to a bug introduced in #19 (#25)

## [1.0.0] - 2019-12-06
### Added
* Support for disabling cache on the call for the role list (#9)
* Support for overriding id_token_for_roles_url in the config (#9)
* Support to trigger group role map rebuild (#12)

### Changed
* To whitelisting all HTTP headers (#12)
* The URL of ID_TOKEN_FOR_ROLES_URL from ending with /roles to be the root URL.
  This is a breaking change. (#12)

## [0.2.0] - 2019-11-18
### Changed
* Hosted AWS account to mozilla-iam (#6)

### Security
* Mitigated reflected XSS vulnerability due to left over debugging logic (#8)

## [0.1.0] - 2019-11-11
### Added
* HTTP to HTTPS redirect by adding CloudFront (#4)

## [0.0.1] - 2019-11-06
### Added
* A working implementation of the federated AWS RP (#1)

[Unreleased]: https://github.com/mozilla-iam/federated-aws-rp/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/mozilla-iam/federated-aws-rp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/mozilla-iam/federated-aws-rp/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/mozilla-iam/federated-aws-rp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mozilla-iam/federated-aws-rp/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/mozilla-iam/federated-aws-rp/releases/tag/v0.0.1
