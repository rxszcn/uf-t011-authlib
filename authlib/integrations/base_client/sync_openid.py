import time

from joserfc import jwt
from joserfc.errors import BadSignatureError
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

from authlib.common.security import generate_token
from authlib.common.urls import add_params_to_uri
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core import UserInfo


def _get_id_token_algorithms(metadata):
    """Return the algorithms accepted for the ID token signature."""
    algorithms = metadata.get("id_token_signing_alg_values_supported") or []
    if isinstance(algorithms, str):
        algorithms = [algorithms]

    algorithms = [alg for alg in algorithms if alg != "none"]

    # Per OpenID Connect Registration §2, a client receives RS256 ID tokens
    # by default.
    return algorithms or ["RS256"]


def _get_claims_options(claims_options, metadata):
    """Add the issuer check to the claims options, unless they check the
    issuer themselves.
    """
    claims_options = {
        key: dict(option) for key, option in (claims_options or {}).items()
    }
    issuer = metadata.get("issuer")
    if not issuer:
        return claims_options

    iss = claims_options.setdefault("iss", {})
    if not {"value", "values", "validate"} & iss.keys():
        iss["values"] = [issuer]

    return claims_options


def _may_refresh_jwk_set(client):
    """Tell if the JWK set can be fetched again, at most once per
    ``jwks_refresh_interval`` seconds.

    The rate limit applies whatever made the cached key set fail: an unknown
    ``kid`` (a key is missing) or a signature that does not verify (the key
    for the token is not the cached one, for instance an ID token without a
    ``kid`` after the provider rotated its keys).
    """
    now = time.monotonic()
    refreshed_at = client._jwk_set_refreshed_at
    if refreshed_at is not None and now - refreshed_at < client.jwks_refresh_interval:
        return False

    client._jwk_set_refreshed_at = now
    return True


def _decode_id_token(value, jwks, alg_values):
    """Decode an ID token with a JWK set.

    :raises InvalidKeyIdError: the ``kid`` of the token is not in the set,
        or the token has no ``kid`` while the set has several keys.
    :raises BadSignatureError: a key was found, but its signature does not
        verify. This also covers tokens without a ``kid`` verified with the
        only key of the set, for instance after a key rotation.
    """
    key_set = KeySet.import_key_set(jwks)
    return jwt.decode(
        value,
        key=key_set,
        registry=JWSRegistry(algorithms=alg_values, strict_check_header=False),
    )


class OpenIDMixin:
    #: Minimum number of seconds between two fetches of the JWK set caused by
    #: an ID token that cannot be verified with the cached keys: either its
    #: ``kid`` is unknown, or its signature does not match.
    jwks_refresh_interval = 60
    _jwk_set_refreshed_at = None

    def fetch_jwk_set(self, force=False):
        metadata = self.load_server_metadata()
        jwk_set = metadata.get("jwks")
        if jwk_set and not force:
            return jwk_set

        uri = metadata.get("jwks_uri")
        if not uri:
            raise RuntimeError('Missing "jwks_uri" in metadata')

        with self._get_session() as session:
            resp = session.request("GET", uri, withhold_token=True)
            resp.raise_for_status()
            jwk_set = resp.json()

        self.server_metadata["jwks"] = jwk_set
        return jwk_set

    def userinfo(self, **kwargs):
        """Fetch user info from ``userinfo_endpoint``."""
        metadata = self.load_server_metadata()
        resp = self.get(metadata["userinfo_endpoint"], **kwargs)
        resp.raise_for_status()
        data = resp.json()
        return UserInfo(data)

    def parse_id_token(
        self, token, nonce, claims_options=None, claims_cls=None, leeway=120
    ):
        """Return UserInfo after validating the token's ``id_token``.

        The expected ``nonce`` is controlled by the application. Token claims
        such as ``nonce_supported`` cannot disable its validation.
        """
        if "id_token" not in token:
            return None

        claims_params = dict(
            nonce=nonce,
            client_id=self.client_id,
        )

        if claims_cls is None:
            if "access_token" in token:
                claims_params["access_token"] = token["access_token"]
                claims_cls = CodeIDToken
            else:
                claims_cls = ImplicitIDToken

        metadata = self.load_server_metadata()
        claims_options = _get_claims_options(claims_options, metadata)
        alg_values = _get_id_token_algorithms(metadata)

        id_token_value = token["id_token"]
        try:
            token = _decode_id_token(id_token_value, self.fetch_jwk_set(), alg_values)
        except (InvalidKeyIdError, BadSignatureError):
            # Two rotation symptoms share the same remedy, a forced fetch:
            # InvalidKeyIdError means the signing key is absent from the
            # cached set; BadSignatureError means a key was selected but its
            # signature does not verify, which is what tokens without a
            # ``kid`` raise when the provider rotated its only key.
            if not _may_refresh_jwk_set(self):
                raise

            # Without a jwks_uri, fetch_jwk_set raises a RuntimeError rather
            # than silently keeping a key set the application set statically.
            token = _decode_id_token(
                id_token_value, self.fetch_jwk_set(force=True), alg_values
            )

        claims = claims_cls(token.claims, token.header, claims_options, claims_params)
        claims.validate(leeway=leeway)
        return UserInfo(claims)

    def create_logout_url(
        self,
        post_logout_redirect_uri=None,
        id_token_hint=None,
        state=None,
        **kwargs,
    ):
        """Generate the end session URL for RP-Initiated Logout.

        :param post_logout_redirect_uri: URI to redirect after logout.
        :param id_token_hint: ID Token previously issued to the RP.
        :param state: Opaque value for maintaining state.
        :param kwargs: Extra parameters (client_id, logout_hint, ui_locales).
        :return: dict with 'url' and 'state' keys.
        """
        metadata = self.load_server_metadata()
        end_session_endpoint = metadata.get("end_session_endpoint")

        if not end_session_endpoint:
            raise RuntimeError('Missing "end_session_endpoint" in metadata')

        params = {}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
            if state is None:
                state = generate_token(20)
            params["state"] = state

        for key in ("client_id", "logout_hint", "ui_locales"):
            if key in kwargs:
                params[key] = kwargs[key]

        url = add_params_to_uri(end_session_endpoint, params)
        return {"url": url, "state": state}
