# Changelog

## v0.2.4 (2023-08-20)

* Fixed bug in `Assent.JWTAdapter.AssentJWT` where `verified?` could be a `{:error, term()}` tuple rather than boolean
* Improved message on private key file load error

## v0.2.3 (2023-03-23)

* Removed `:castore` version requirement
* `Assent.Strategy.Httpc.request/5` raises error when SSL certificate can't be validated

## v0.2.2 (2023-02-27)

* Fixed bug to handle 201 success response
* `Assent.Strategy.OIDC` now has support for multiple audiences
* `Assent.Strategy.OIDC` now permits any auth method if no `token_endpoint_auth_methods_supported` specified
* `Assent.Strategy.Linkedin` added

## v0.2.1 (2022-09-15)

* Default to using `Jason` instead of `Poison` for JSON parsing
* Fixed `Bitwise` warning when running on Elixir 1.14

## v0.2.0 (2022-03-01)

**This release consists of breaking changes.**

In previous `Assent.Strategy.Slack` strategy, the `sub` user id field consisted of `{SUB}-{TEAM}`. Slack has migrated to OpenID Connect, and the response has been conformed to OIDC. The `sub` will now only consists of the `sub` id, and not include team id. To succesfullly migrate to this release all slack identity records storing the `sub` user id field has to be updated.

If you wish to continue using the previous `sub` user id a custom OIDC strategy can be used instead:

```elixir
defmodule Slack do
  use Assent.Strategy.OIDC.Base

  alias Assent.Strategy.Slack

  defdelegate default_config(config), to: Slack

  def normalize(config, user) do
    user = Map.put(user, "sub", "#{user["https://slack.com/user_id"]}-#{user["https://slack.com/team_id"]}")

    Slack.normalize(config, user)
  end
end
```

* `Assent.Strategy.OIDC.fetch_user/2` now removes the ID token specific keys from the user claims instead of normalizing
* `Assent.Strategy.OIDC.Base` now adds `normalize/2` to the macro that will include the full user claims in the user params
* `Assent.Strategy.Slack` now uses OpenID connect instead of legacy OAuth 2.0, please note that the `sub` value may have changed

## v0.1.28 (2021-09-30)

* `Assent.Strategy.OIDC` bug fixed so it handles unreachable urls correctly

## v0.1.27 (2021-08-21)

* `Assent.Strategy.OIDC` bug fixed for `normalize/2` macro callback

## v0.1.26 (2021-05-27)

* `Assent.constant_time_compare/2` no longer outputs a deprecation warning for OTP 24

## v0.1.25 (2021-04-09)

* `Assent.Strategy.Apple` has been fixed to handle the JSON encoded user in callback params

## v0.1.24 (2021-03-22)

* `Assent.Strategy.OIDC.Base.authorize_url/2` now has correct type specs

## v0.1.23 (2021-03-01)

Updated to support OTP 24 and no longer support OTP < 22.1

* `Assent.Strategy.OIDC` now handles missing `id_token` in token params

## v0.1.22 (2021-01-08)

* `Assent.Strategy.OAuth2.fetch_user/4` now accepts headers in arguments
* `Assent.Strategy.AzureAD` bug fixed so it now uses the `RS256` alg

## v0.1.21 (2020-12-29)

* `Assent.Strategy.OAuth` now handles missing params in callback phase
* `Assent.Strategy.Twitter` now handles access denied callback

## v0.1.20 (2020-12-10)

* `Assent.Strategy.Stripe` added
* `Assent.Strategy.to_url/3` now handles nested query params
* `Assent.Strategy.OAuth2` no longer removes padding for base64 encoding authorization header
* `Assent.Strategy.OIDC.validate_id_token/2` now supports dynamic OpenID configuration
* `Assent.Strategy.OIDC.fetch_userinfo/2` now supports dynamic OpenID configuration

## v0.1.19 (2020-11-25)

* Updated docs to detail `:inets` compilation
* `Assent.OAuth2.authorize_url/1` now returns the state, if defined, from `authorization_params`

## v0.1.18 (2020-11-08)

* Removed `oauther` dependency

## v0.1.17 (2020-11-05)

* Relax `mint` requirement

## v0.1.16 (2020-10-21)

**Warning:** This release has breaking changes.

All `get_user/2` functions has been renamed to `fetch_user/2` as they return `{:ok, res}`/`{:error, res}` tuples.

* `Assent.OAuth.get/4` removed in favor of `Assent.OAuth.request/6`
* `Assent.OAuth2.get_access_token/3` renamed to `Assent.OAuth2.grant_access_token/3`
* `Assent.OAuth2.get/4` removed in favor of `Assent.OAuth2.request/6`

## v0.1.15 (2020-10-18)

* `Assent.Strategy.OIDC.validate_id_token/2` has a bug fixed where `alg` was not validated correctly
* `Assent.Strategy.OIDC` now has an `:id_token_signed_response_alg` configuration option
* `Assent.Strategy.LINE` added

## v0.1.14 (2020-10-11)

* `Assent.Strategy.OAuth2.get_access_token/3` added
* `Assent.Strategy.OAuth2.refresh_access_token/3` added
* `Assent.Strategy.OAuth2.authorization_headers/2` is no long a public function
* `Assent.Strategy.Apple` updated to handle `name` scope

## v0.1.13 (2020-07-14)

* `Assent.Strategy.DigitalOcean` added

## v0.1.12 (2020-05-24)

* `Assent.Strategy.OAuth2.authorization_headers/2` now capitalizes the token type in the authorization header
* `Assent.Strategy.OIDC.callback/2` now calls the strategy `get_user/2` method before any ID token validation
* `Assent.Strategy.OIDC.validate_id_token/2` added
* `Assent.Strategy.OIDC.fetch_userinfo/2` added
* `Assent.Strategy.OIDC` no longer fetches the userinfo by default instead using the claims in the ID Token

## v0.1.11 (2020-05-16)

* `Assent.Strategy.OAuth2.callback/2` now requires `:session_params` to be set in the config
* `Assent.Strategy.OIDC.callback/2` now requires `:session_params` to be set in the config
* `Assent.Strategy.OAuth2` now uses constant time comparison for state
* `Assent.Strategy.OIDC` now uses constant time comparison for nonce
* `Assent.Strategy.Httpc.request/5` bug fixed for certificates that has wildcard domain with SAN extension
* `Assent.Strategy.Mint.request/5` bug fixed for certificates that has wildcard domain with SAN extension

## v0.1.10 (2020-04-23)

Now requires Mint 1.0.0 or higher.

* `Assent.Strategy.Instagram` now accepts `:user_url_request_fields` config option and passes `fields` params to the `/me` point

## v0.1.9 (2020-04-23)

Now requires Elixir 1.7 or higher.

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
