"""Regras específicas para arquivos de configuração de ambiente."""

from pathlib import PurePosixPath
import re

from leak_hunt.regras.base import Regra


_MODELOS_ENV = frozenset({".env.example", ".env.sample", ".env.template", ".env.dist"})


def _arquivo_env_real(arquivo: str) -> bool:
    nome = PurePosixPath(arquivo).name.lower()
    return (nome == ".env" or nome.startswith(".env.")) and nome not in _MODELOS_ENV


def _valor_env_nao_vazio(correspondencia: re.Match[str], texto: str) -> bool:
    del texto
    valor = correspondencia.group("valor").strip()
    if not valor or valor.startswith("#"):
        return False
    if valor[:1] in {'"', "'"} and valor[-1:] == valor[:1]:
        return bool(valor[1:-1].strip())
    return bool(valor.split(" #", maxsplit=1)[0].strip())


REGRAS_AMBIENTE = (
    Regra(
        codigo="env-value",
        tipo="Valor versionado em arquivo .env",
        padrao=re.compile(
            r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?P<valor>.*)$"
        ),
        validador=_valor_env_nao_vazio,
        validador_arquivo=_arquivo_env_real,
        grupo_valor="valor",
        severidade="alto",
    ),
)
