# Changelog

## v0.3.0 (TBA)

**This release consists of breaking changes.**

Userinfo is now cast to the correct type per https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1. When upgrading you must ensure that you do not depend on a specific type in the returned userinfo for any of the strategies listed below.

### Breaking changes

* `Assent.Strategy.Auth0.authorize_url/2` no longer accepts `:domain` config, use `:base_url` instead
* `Assent.Strategy.Basecamp.callback/2` now encodes `sub` as a `binary()` instead of an `integer()`
* `Assent.Strategy.Github.callback/2` now encodes `sub` as a `binary()` instead of an `integer()`
* `Assent.Strategy.Google` now encodes `email_verified` as a `boolean()` instead of a `binary()`
* `Assent.Strategy.Google` now return `hd` instead of `google_hd`
* `Assent.Strategy.Strava.callback/2` now encodes `sub` as a `binary()` instead of an `integer()`
* `Assent.Strategy.Telegram.callback/2` now encodes `sub` as a `binary()` instead of an `integer()`
* `Assent.Strategy.Twitter.callback/2` now encodes `sub` as a `binary()` instead of an `integer()`
* `Assent.Strategy.VK.callback/2` now encodes `sub` as a `binary()` instead of an `integer()`
* `:site` configuration option removed, use `:base_url` instead
* `Assent.Strategy.OAuth2.authorize_url/2` no longer allows `:state` in `:authorization_params`
* `Assent.Strategy.decode_response/2`removed, use `Assent.HTTPAdapter.decode_response/2` instead
* `Assent.Strategy.request/5` removed, use `Assent.Strategy.http_request/5` instead
* `Assent.Strategy.prune/1` removed
* `Assent.MissingParamError` no longer accepts `:expected_key`, use `:key` instead
* `Assent.HTTPAdapter.Mint` removed
* `Assent.Config` removed

### Changes

* `Assent.Strategy.Auth0` now uses OIDC instead of OAuth 2.0 base strategy
* `Assent.Strategy.Gitlab` now uses OIDC instead of OAuth 2.0 base strategy
* `Assent.Strategy.Google` now uses OIDC instead of OAuth 2.0 base strategy
* `Assent.Strategy.normalize_userinfo/2` now casts the user claims per OpenID specification

## v0.2

The CHANGELOG for v0.2 releases can be found [in the v0.2 branch](https://github.com/pow-auth/assent/blob/v0.2/CHANGELOG.md).