"""Regras para formatos de segredo usados internacionalmente."""

import re

from leak_hunt.regras.base import Regra


_EXEMPLOS_AWS = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAI44QH8DHBEXAMPLE",
    }
)
_EXEMPLO_JWT_IO = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


REGRAS_GENERICAS = (
    Regra(
        codigo="aws-access-key",
        tipo="AWS Access Key",
        padrao=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        valores_permitidos=_EXEMPLOS_AWS,
        severidade="critico",
    ),
    Regra(
        codigo="private-key",
        tipo="Chave privada",
        padrao=re.compile(
            r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----"
        ),
        severidade="critico",
    ),
    Regra(
        codigo="jwt",
        tipo="JSON Web Token (JWT)",
        padrao=re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\."
            r"eyJ[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])"
        ),
        valores_permitidos=frozenset({_EXEMPLO_JWT_IO}),
        severidade="alto",
    ),
    Regra(
        codigo="github-pat",
        tipo="Token de acesso GitHub",
        padrao=re.compile(
            r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36}"
            r"(?![A-Za-z0-9_])"
        ),
        severidade="critico",
    ),
)
