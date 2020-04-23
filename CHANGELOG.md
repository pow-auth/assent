# Changelog

## v0.1.9 (TBA)

* `Assent.Strategy.Instagram` now uses the Instagram Graph API
* `Assent.Strategy.OIDC` bug fixed when no `:session_params` set in config

## v0.1.8 (2020-02-15)

* `Assent.Strategy.Github` now provides `email_verified` value
* `Assent.Strategy.Gitlab` now provides `email_verified` value
* `Assent.Strategy.Google` fixed to provide correct `email_verified` value
* `Assent.Strategy.Twitter` now provides `email_verified` value

## v0.1.7 (2020-02-10)

* Fix `Assent.HTTPAdapter.Mint` where `:unknown` responses where not handled correctly

## v0.1.6 (2020-01-30)

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
