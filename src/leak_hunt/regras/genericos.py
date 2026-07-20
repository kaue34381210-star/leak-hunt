"""Regras para formatos de segredo usados internacionalmente."""

import re

from leak_hunt.regras.base import Regra


REGRAS_GENERICAS = (
    Regra(
        codigo="aws-access-key",
        tipo="AWS Access Key",
        padrao=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    Regra(
        codigo="private-key",
        tipo="Chave privada",
        padrao=re.compile(
            r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----"
        ),
    ),
    Regra(
        codigo="jwt",
        tipo="JSON Web Token (JWT)",
        padrao=re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\."
            r"eyJ[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\b"
        ),
    ),
)
