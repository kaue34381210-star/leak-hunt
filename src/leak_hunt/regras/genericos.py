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
_CONTEXTO_OPENAI = re.compile(
    r"(?:\bopenai\b|\bOPENAI_(?:API|ADMIN)_KEY\b)",
    re.IGNORECASE,
)


def _chave_openai_em_contexto(
    correspondencia: re.Match[str],
    texto: str,
) -> bool:
    del correspondencia
    return _CONTEXTO_OPENAI.search(texto) is not None


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
            r"(?<![A-Za-z0-9_])(?:"
            r"gh[pour]_[A-Za-z0-9]{36}|"
            r"ghs_(?:[A-Za-z0-9]{36}|[A-Za-z0-9]+_[A-Za-z0-9._-]{20,})|"
            r"github_pat_[A-Za-z0-9_]{20,255}"
            r")"
            r"(?![A-Za-z0-9_])"
        ),
        severidade="critico",
    ),
    Regra(
        codigo="google-api-key",
        tipo="Google API Key",
        padrao=re.compile(
            r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}"
            r"(?![A-Za-z0-9_-])"
        ),
        severidade="alto",
    ),
    Regra(
        codigo="slack-token",
        tipo="Token Slack",
        padrao=re.compile(
            r"(?<![A-Za-z0-9-])(?:xox[abprs]|xapp|xwfp)-"
            r"[0-9A-Za-z-]{20,}(?![A-Za-z0-9-])"
        ),
        valores_permitidos=frozenset({"xapp-1-A0123456789-example"}),
        severidade="critico",
    ),
    Regra(
        codigo="stripe-live-key",
        tipo="Chave secreta Stripe live",
        padrao=re.compile(
            r"(?<![A-Za-z0-9_])(?:sk|rk)_live_[0-9A-Za-z]{24,}"
            r"(?![A-Za-z0-9_])"
        ),
        severidade="critico",
    ),
    Regra(
        codigo="openai-api-key",
        tipo="OpenAI API Key",
        padrao=re.compile(
            r"(?<![A-Za-z0-9_-])sk-(?!ant-)"
            r"(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"
            r"(?![A-Za-z0-9_-])"
        ),
        validador=_chave_openai_em_contexto,
        severidade="critico",
    ),
    Regra(
        codigo="anthropic-api-key",
        tipo="Anthropic API Key",
        padrao=re.compile(
            r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{30,}"
            r"(?![A-Za-z0-9_-])"
        ),
        severidade="critico",
    ),
    Regra(
        codigo="sendgrid-api-key",
        tipo="SendGrid API Key",
        padrao=re.compile(
            r"(?<![A-Za-z0-9_-])SG\.[A-Za-z0-9_-]{22}\."
            r"[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"
        ),
        severidade="critico",
    ),
)
