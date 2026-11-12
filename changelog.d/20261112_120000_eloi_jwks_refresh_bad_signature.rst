Fixed
~~~~~

- An ID token whose signature does not verify with the cached JWK set now
  fetches the JWK set of the provider again, like an ID token with an unknown
  ``kid``. This happens when the provider rotates its signing keys for
  tokens without a ``kid``, which previously kept failing until the client
  was restarted. The refresh is still limited to one fetch per
  ``jwks_refresh_interval`` seconds, shared by unknown ``kid`` and signature
  failures, so the rate-limit protection against forged ID tokens is kept.
