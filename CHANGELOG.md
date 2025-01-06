# Changelog

## v0.3.0 (TBA)

**This release consists of breaking changes.**

### Breaking changes

* `Assent.Strategy.Auth0.authorize_url/2` no longer accepts `:domain` config, use `:base_url` instead
* `Assent.Strategy.Google` now return `hd` instead of `google_hd`
* `:site` configuration option removed, use `:base_url` instead
* `Assent.Strategy.OAuth2.authorize_url/2` no longer allows `:state` in `:authorization_params`
* `Assent.Strategy.decode_response/2`removed, use `Assent.HTTPAdapter.decode_response/2` instead
* `Assent.Strategy.request/5` removed, use `Assent.Strategy.http_request/5` instead
* `Assent.MissingParamError` no longer accepts `:expected_key`, use `:key` instead
* `Assent.HTTPAdapter.Mint` removed
* `Assent.Config` removed

### Changes

* `Assent.Strategy.Auth0` now uses OIDC instead of OAuth 2.0 base strategy
* `Assent.Strategy.Google` now uses OIDC instead of OAuth 2.0 base strategy

## v0.2

The CHANGELOG for v0.2 releases can be found [in the v0.2 branch](https://github.com/pow-auth/assent/blob/v0.2/CHANGELOG.md).