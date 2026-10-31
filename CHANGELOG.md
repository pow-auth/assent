# Changelog

## v0.4.0 (TBA)

Now requires Elixir 1.18 / OTP 26.

### Breaking changes

* `Assent.HTTPAdapter.Finch` removed
* `JSON` is now the default JSON library

### Changes

* `:inets` is now started automatically by `Assent`, and no longer required in `:extra_applications`
* `Assent.JWTAdapter.AssentJWT` now supports EdDSA algorithms
* `Assent.JWTAdapter.AssentJWT` now supports EC JWKs
* `Assent.Strategy.OIDC` no longer rejects a `:client_authentication_method` missing from the provider's `token_endpoint_auth_methods_supported`
* `Assent.Strategy.OIDC` accepts additional ID Token issuers via the `:trusted_issuers` config option
* `Assent.Strategy.Facebook` now requests the user `picture` field
* Strategies now accept a `:prepare_http_request` configuration option for rewriting HTTP requests
* `Assent.HTTPAdapter.request/5` is deprecated in favor of `Assent.HTTPAdapter.request/2`
* `Assent.Strategy.Apple` no longer allows unverified `user` callback parameters to override identity claims
* `Assent.Strategy.Apple` now returns `is_private_email`, `real_user_status`, and `org_id` in the user info
* `Assent.Strategy.cast_claims/2` added to support casting provider-specific claims

### Bug fixes

* `Assent.Strategy.OAuth` no longer lowercases the request path for signature base string, per RFC 5849 3.4.1.2
* `Assent.HTTPAdapter.Req` now returns the response headers instead of the request headers
* `Assent.Strategy.OIDC` now rejects dynamically fetched OpenID configuration when issuer does not match the issuer URL
* `Assent.Strategy.OAuth2.callback/2` now validates the `state` parameter before handling error responses
* `Assent.Strategy.OIDC.authorize_url/1` now generates a random nonce when `:nonce` is set to `true`
* `Assent.Strategy.OAuth.authorize_url/1` now validates `oauth_callback_confirmed` in request token responses
* `Assent.Strategy.OAuth.callback/2` now validates the `oauth_token` parameter
* `Assent.Strategy.Telegram.callback/2` now verifies `hash` before verifying `auth_date`

## v0.3

The CHANGELOG for v0.3 releases can be found [in the v0.2 branch](https://github.com/pow-auth/assent/blob/v0.3/CHANGELOG.md).
