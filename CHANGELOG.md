# Changelog

## v0.1.6 (TBA)

* `Assent.Strategy.AzureAD` now uses auth code flow instead of hybrid flow

## v0.1.5 (2020-01-13)

* Removed unused `:resource` param in `Assent.Strategy.AzureAD`
* Added "email profile" to scope in `Assent.Strategy.AzureAD`
* Use `response_mode=form_post` for `Assent.Strategy.AzureAD`
* Updated `Assent.Strategy.OAuth2` to handle access token request correctly when `:auth_method` is `nil` per RFC specs
* Changed `Assent.Strategy.Apple` to use OIDC strategy and verify the JWT
* Changed `Assent.Strategy.OIDC` to update token with the expanded JWT as the `id_token`
* Fixed bug in `Assent.HTTPAdapter.Mint` with query params not being included in request

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
