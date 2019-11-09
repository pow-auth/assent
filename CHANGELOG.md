# Changelog

## v0.1.4 (2019-11-09)

* Support mint up to `v1.0.x`
* Fixed bug in `Assent.JWTAdapter.JOSE` where `nil` secret value raised an exception
* Fixed bug in `Assent.JWTAdapter.AssentJWT` where ECDSA algorithms didn't generate or verify valid signatures

## v0.1.3 (2019-10-27)

* Fixed bug in `Assent.Strategy.Github` where multiple emails for account resulted in the verified primary e-mail not being returned

## v0.1.2 (2019-10-08)

* Require `:redirect_uri` is set in the config of `Assent.Strategy.OAuth2.callback/3` instead of as `redirect_uri` in the params

## v0.1.1 (2019-10-07)

* Relax mint requirement
* Fix bug in `Assent.HTTPAdapter.Mint` where HTTP/2 responses wasn't parsed correctly

## v0.1.0 (2019-10-06)

* Initial release
