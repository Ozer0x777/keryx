"""Authentification unique OpenID Connect (Keycloak) : code d'autorisation + PKCE, vérification stricte du jeton.

[OpenID Connect Core 1.0 ; RFC 6749, RFC 7636 (PKCE), RFC 9700 (bonnes pratiques de sécurité OAuth 2.0) ;
PDIS IV.3.9.d annuaire centralisé] Contrôles appliqués au jeton d'identité : algorithme de signature dans une liste
blanche (jamais « none » ni HS*), signature vérifiée avec les clés publiques (JWKS) de l'émetteur, émetteur égal à celui
configuré, audience contenant l'identifiant du client, expiration, nonce égal à celui de la requête, présence de « sub ».
L'émetteur doit être en HTTPS (HTTP uniquement pour un essai local explicitement autorisé).
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse

import httpx
import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

ALLOWED_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256")
HTTP_TIMEOUT = 8.0
KNOWN_ROLES = ("admin", "manager", "analyst", "client")
DEFAULT_SSO_ROLES = ("manager", "analyst", "client")


class OidcError(Exception):
    """Erreur de connexion SSO : le message est destiné à l'utilisateur, sans détail interne."""


@dataclass
class Provider:
    name: str
    label: str
    issuer: str
    client_id: str
    client_secret: str | None = None
    scopes: str = "openid profile email"
    # Rôles Keryx que ce fournisseur peut authentifier. Jamais « admin » par défaut : l'Admin garde l'authentification
    # locale (accès de secours), et un realm ne doit pas pouvoir prendre un compte d'un autre périmètre (ADR-0017).
    roles: tuple[str, ...] = DEFAULT_SSO_ROLES


def load_providers(raw: str | None, allow_http: bool) -> dict[str, Provider]:
    if not raw:
        return {}
    try:
        items = json.loads(raw)
        providers = {}
        for it in items:
            p = Provider(name=str(it["name"]), label=str(it.get("label") or it["name"]), issuer=str(it["issuer"]).rstrip("/"),
                         client_id=str(it["client_id"]), client_secret=it.get("client_secret"),
                         scopes=str(it.get("scopes") or "openid profile email"))
            if "roles" in it:
                roles = it["roles"]
                if not isinstance(roles, list) or not roles or any(r not in KNOWN_ROLES for r in roles):
                    raise ValueError(f"rôles du fournisseur « {p.name} » : liste non vide parmi {', '.join(KNOWN_ROLES)}")
                p.roles = tuple(dict.fromkeys(roles))
            if not p.name.replace("-", "").replace("_", "").isalnum():
                raise ValueError("nom de fournisseur invalide")
            u = urlparse(p.issuer)
            if u.scheme != "https" and not (allow_http and u.scheme == "http"):
                raise ValueError(f"l'émetteur du fournisseur « {p.name} » doit être en HTTPS")
            providers[p.name] = p
        return providers
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"KERYX_OIDC_PROVIDERS invalide : {exc}") from exc


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class Discovery:
    """Métadonnées de l'émetteur et clés publiques, mises en cache quelques minutes."""

    def __init__(self, provider: Provider, http: httpx.Client | None = None):
        self.p, self.http = provider, http or httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False)
        self._meta: dict | None = None
        self._meta_at = 0.0
        self._jwks: dict | None = None
        self._jwks_at = 0.0

    def meta(self) -> dict:
        if self._meta is None or time.monotonic() - self._meta_at > 600:
            try:
                r = self.http.get(f"{self.p.issuer}/.well-known/openid-configuration")
                r.raise_for_status()
                m = r.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise OidcError("Le fournisseur d'identité est injoignable.") from exc
            if str(m.get("issuer", "")).rstrip("/") != self.p.issuer:  # RFC 8414 §3.3 : l'émetteur annoncé doit correspondre
                raise OidcError("Réponse du fournisseur d'identité incohérente.")
            self._meta, self._meta_at = m, time.monotonic()
        return self._meta

    def keys(self, force: bool = False) -> list[dict]:
        if force or self._jwks is None or time.monotonic() - self._jwks_at > 600:
            try:
                r = self.http.get(self.meta()["jwks_uri"])
                r.raise_for_status()
                self._jwks = r.json()
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                raise OidcError("Clés de signature du fournisseur indisponibles.") from exc
            self._jwks_at = time.monotonic()
        return self._jwks.get("keys", [])

    def authorization_url(self, redirect_uri: str, state: str, nonce: str, challenge: str) -> str:
        q = urlencode({"response_type": "code", "client_id": self.p.client_id, "redirect_uri": redirect_uri,
                       "scope": self.p.scopes, "state": state, "nonce": nonce, "code_challenge": challenge,
                       "code_challenge_method": "S256"})
        return f"{self.meta()['authorization_endpoint']}?{q}"

    def logout_url(self, id_token_hint: str, post_logout_redirect_uri: str) -> str | None:
        """Adresse de déconnexion du fournisseur (OIDC RP-Initiated Logout 1.0), ou None s'il ne la propose pas."""
        endpoint = self.meta().get("end_session_endpoint")
        if not endpoint:
            return None
        return f"{endpoint}?" + urlencode({"id_token_hint": id_token_hint, "client_id": self.p.client_id,
                                           "post_logout_redirect_uri": post_logout_redirect_uri})

    def verify_logout(self, logout_token: str) -> dict:
        return verify_logout_token(logout_token, self.keys, self.p.issuer, self.p.client_id, now=time.time())

    def exchange(self, code: str, redirect_uri: str, verifier: str) -> str:
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                "client_id": self.p.client_id, "code_verifier": verifier}
        auth = (self.p.client_id, self.p.client_secret) if self.p.client_secret else None
        try:
            r = self.http.post(self.meta()["token_endpoint"], data=data, auth=auth)
            body = r.json()
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise OidcError("Échange du code d'autorisation impossible.") from exc
        if r.status_code != 200 or not body.get("id_token"):
            raise OidcError("Le fournisseur d'identité a refusé la connexion.")
        return body["id_token"]

    def verify(self, id_token: str, nonce: str, required_acr: str | None = None) -> dict:
        return verify_id_token(id_token, self.keys, self.p.issuer, self.p.client_id, nonce, required_acr)


def _public_key(jwk: dict):
    kty = jwk.get("kty")
    if kty == "RSA":
        return RSAAlgorithm.from_jwk(json.dumps(jwk))
    if kty == "EC":
        return ECAlgorithm.from_jwk(json.dumps(jwk))
    raise OidcError("Type de clé non pris en charge.")


def verify_id_token(token: str, get_keys, issuer: str, client_id: str, nonce: str,
                    required_acr: str | None = None, now: float | None = None) -> dict:
    """Vérifie le jeton d'identité et renvoie ses revendications. `get_keys(force=False)` renvoie la liste JWKS."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise OidcError("Jeton d'identité illisible.") from exc
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:  # refuse « none » et les algorithmes symétriques (confusion de clé)
        raise OidcError("Algorithme de signature refusé.")
    kid = header.get("kid")

    def find(force: bool):
        keys = [k for k in get_keys(force) if (kid is None or k.get("kid") == kid) and k.get("use", "sig") == "sig"]
        return keys[0] if keys else None
    jwk = find(False) or find(True)  # clé inconnue : rafraîchir une fois (rotation des clés)
    if jwk is None:
        raise OidcError("Clé de signature inconnue.")
    try:
        claims = jwt.decode(token, _public_key(jwk), algorithms=[alg], audience=client_id, issuer=issuer, leeway=60,
                            options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    except jwt.ExpiredSignatureError as exc:
        raise OidcError("Jeton d'identité expiré.") from exc
    except jwt.PyJWTError as exc:
        raise OidcError("Jeton d'identité invalide.") from exc
    if now is not None and claims["exp"] < now:
        raise OidcError("Jeton d'identité expiré.")
    aud = claims["aud"]
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != client_id:
        raise OidcError("Jeton d'identité destiné à plusieurs clients sans « azp » valide.")
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OidcError("Nonce invalide.")
    if required_acr and str(claims.get("acr", "")) != required_acr:
        raise OidcError("Niveau d'authentification insuffisant (double authentification exigée).")
    return claims


BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def verify_logout_token(token: str, get_keys, issuer: str, client_id: str, now: float | None = None) -> dict:
    """Jeton de déconnexion (OpenID Connect Back-Channel Logout 1.0, section 2.6) : signature et algorithme comme un jeton
    d'identité, émetteur, audience, « iat » et « jti » présents, événement de déconnexion, « sid » ou « sub », et
    jamais de « nonce » (un jeton d'identité ne doit pas pouvoir servir de jeton de déconnexion)."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise OidcError("Jeton de déconnexion illisible.") from exc
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise OidcError("Algorithme de signature refusé.")
    kid = header.get("kid")

    def find(force: bool):
        keys = [k for k in get_keys(force) if (kid is None or k.get("kid") == kid) and k.get("use", "sig") == "sig"]
        return keys[0] if keys else None
    jwk = find(False) or find(True)
    if jwk is None:
        raise OidcError("Clé de signature inconnue.")
    try:
        claims = jwt.decode(token, _public_key(jwk), algorithms=[alg], audience=client_id, issuer=issuer, leeway=60,
                            options={"require": ["iat", "iss", "aud", "jti"], "verify_exp": True})
    except jwt.PyJWTError as exc:
        raise OidcError("Jeton de déconnexion invalide.") from exc
    if now is not None and "exp" in claims and claims["exp"] < now:
        raise OidcError("Jeton de déconnexion expiré.")
    if now is not None and claims["iat"] > now + 60:
        raise OidcError("Jeton de déconnexion émis dans le futur.")
    events = claims.get("events")
    if not isinstance(events, dict) or not isinstance(events.get(BACKCHANNEL_EVENT), dict):
        raise OidcError("Événement de déconnexion absent.")
    if "nonce" in claims:
        raise OidcError("Un jeton de déconnexion ne porte pas de nonce.")
    sid, sub = claims.get("sid"), claims.get("sub")
    if not (isinstance(sid, str) and sid) and not (isinstance(sub, str) and sub):
        raise OidcError("Ni « sid » ni « sub » dans le jeton de déconnexion.")
    return claims
