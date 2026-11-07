# Changelog

## v0.4.0 (TBA)

Now requires Elixir 1.18 / OTP 26.

### Breaking changes

* `Assent.HTTPAdapter.Finch` removed
* `JSON` is now the default JSON library
* `Assent.Strategy.Instagram` removed because the Instagram Basic Display API has been discontinued
* Exceptions and `Assent.HTTPAdapter.HTTPResponse` now omit potentially sensitive fields from their default `Inspect` output
* `Assent.Strategy.OIDC` now requires `:userinfo_signed_response_alg` for signed UserInfo responses
* The following exceptions have been renamed:
  - `Assent.CallbackError` to `Assent.Strategy.CallbackError`, now with `:params` field instead of `:error` and `:error_uri`
  - `Assent.CallbackCSRFError` to `Assent.Strategy.CallbackCSRFError`
  - `Assent.CastClaimsError` to `Assent.Strategy.CastError`
  - `Assent.RequestError` to `Assent.HTTPAdapter.RequestError`
  - `Assent.InvalidResponseError` to `Assent.HTTPAdapter.InvalidResponseError`
  - `Assent.UnexpectedResponseError` to `Assent.HTTPAdapter.UnexpectedResponseError`
  - `Assent.ServerUnreachableError` to `Assent.HTTPAdapter.ServerUnreachableError`
* Strategies now return exceptions instead of error strings: `Assent.MissingParamError` for missing parameters and `ArgumentError` for configuration errors
* `Assent.Strategy.OAuth2` now returns `Assent.Strategy.OAuth2.UnsupportedTokenTypeError` for unsupported token types
* `Assent.Strategy.OIDC` now returns:
  - `Assent.Strategy.OIDC.InvalidOpenIDConfigurationError` for invalid provider configuration
  - `Assent.Strategy.OIDC.InvalidIDTokenError` for invalid ID Tokens
  - `Assent.Strategy.OIDC.InvalidUserInfoError` for invalid UserInfo responses
* `Assent.Strategy.Telegram` now returns `ArgumentError` for an invalid `:authorization_channel`
* `Assent.HTTPAdapter.HTTPResponse` replaces its `:request_url` field with a `:request` field containing an `Assent.HTTPAdapter.HTTPRequest` struct
* `Assent.JWTAdapter.AssentJWT.Error` replaces its `:message` field with structured `:action`, `:part`, and `:reason` fields
* `Assent.HTTPAdapter.Httpc` now verifies SSL certificates with the OS trust store and OTP's built-in hostname verification, `:certifi` and `:ssl_verify_fun` are no longer used
* `Assent.HTTPAdapter.Httpc` now raises `ArgumentError` on HTTPS requests configured with `verify: :verify_none`
* `Assent.HTTPAdapter.Httpc` and `Assent.HTTPAdapter.Req` no longer follow redirects by default

### Changes

* `:inets` and `:ssl` are now started automatically by `Assent`, and no longer required in `:extra_applications`
* `Assent.JWTAdapter.AssentJWT` now supports EdDSA algorithms
* `Assent.JWTAdapter.AssentJWT` now supports EC JWKs
* `Assent.Strategy.OIDC` no longer rejects a `:client_authentication_method` missing from the provider's `token_endpoint_auth_methods_supported`
* `Assent.Strategy.OIDC` accepts additional ID Token issuers via the `:trusted_issuers` config option
* `Assent.Strategy.OIDC` now validates `iss` and `aud` for signed UserInfo responses
* `Assent.Strategy.Facebook` now requests the user `picture` field
* Strategies now accept a `:prepare_http_request` configuration option for rewriting HTTP requests
* `Assent.HTTPAdapter.request/5` is deprecated in favor of `Assent.HTTPAdapter.request/2`
* `Assent.Strategy.Apple` now returns `is_private_email`, `real_user_status`, and `org_id` in the user info
* `Assent.Strategy.cast_claims/2` was added to support casting provider-specific claims
* `Assent.Strategy.OAuth2.grant_access_token/3` accepts `:jwt_audience` for JWT client authentication
* `Assent.Strategy.OAuth2` deprecates the `:auth_method` configuration option in favor of `:client_authentication_method`
* `Assent.Strategy.OIDC` deprecates string values for the `:client_authentication_method` configuration option in favor of atoms

### Bug fixes

* `Assent.Strategy.OAuth` no longer lowercases the request path for signature base string, per RFC 5849 3.4.1.2
* `Assent.HTTPAdapter.Req` now returns the response headers instead of the request headers
* `Assent.Strategy.OIDC` now rejects dynamically fetched OpenID configuration when issuer does not match the issuer URL
* `Assent.Strategy.OAuth2.callback/2` now validates the `state` parameter before handling error responses
* `Assent.Strategy.OIDC.authorize_url/1` now generates a random nonce when `:nonce` is set to `true`
* `Assent.Strategy.OAuth.authorize_url/1` now validates `oauth_callback_confirmed` in request token responses
* `Assent.Strategy.OAuth.callback/2` now validates the `oauth_token` parameter
* `Assent.Strategy.Telegram.callback/2` now verifies `hash` before verifying `auth_date`
* `Assent.Strategy.OAuth2.grant_access_token/3` now encodes `client_secret_basic` credentials as `x-www-form-urlencoded`
* `Assent.Strategy.OAuth2.grant_access_token/3` now uses the token endpoint URL as the default `aud` for JWT client authentication
* `Assent.Strategy.OAuth2.grant_access_token/3` now includes a unique `jti` in JWT client authentication
* `Assent.Strategy.Facebook` now uses Graph API v26.0
* `Assent.Strategy.VK` now uses API v5.199 and only requests supported user fields
* `Assent.Strategy.VK` now merges `:user_url_params` with the default `fields` and `v` request params instead of dropping them
* `Assent.Strategy.Discord` now uses the API v10 endpoints
* `Assent.Strategy.Bitbucket` and `Assent.Strategy.Spotify` now use `client_secret_basic` authentication
* `Assent.Strategy.LINE` now uses `client_secret_post` authentication
* `Assent.Strategy.Apple` no longer allows unverified `user` callback parameters to override identity claims

## v0.3

The CHANGELOG for v0.3 releases can be found [in the v0.2 branch](https://github.com/pow-auth/assent/blob/v0.3/CHANGELOG.md).
