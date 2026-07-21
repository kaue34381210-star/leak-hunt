"""Regras de detecção voltadas a documentos e meios de pagamento do Brasil."""

import re

from leak_hunt.regras.base import Regra
from leak_hunt.validadores import validar_cnpj, validar_cpf


_CONTEXTO_PIX = re.compile(
    r"(?:\bpix(?:\b|[_-])|\bdict(?:\b|[_-])|\bchave[_\s-]*pix\b)",
    re.IGNORECASE,
)
_CPF = re.compile(
    r"(?<!\d)(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)"
)
_CNPJ = re.compile(
    r"(?<!\d)(?:\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}|\d{14})(?!\d)"
)


def _tem_contexto_pix(texto: str) -> bool:
    return _CONTEXTO_PIX.search(texto) is not None


def _cpf_pix(correspondencia: re.Match[str], texto: str) -> bool:
    return _tem_contexto_pix(texto) and validar_cpf(correspondencia.group(0))


def _cnpj_pix(correspondencia: re.Match[str], texto: str) -> bool:
    return _tem_contexto_pix(texto) and validar_cnpj(correspondencia.group(0))


def _cpf_hardcoded(correspondencia: re.Match[str], texto: str) -> bool:
    return not _tem_contexto_pix(texto) and validar_cpf(correspondencia.group(0))


def _cnpj_hardcoded(correspondencia: re.Match[str], texto: str) -> bool:
    return not _tem_contexto_pix(texto) and validar_cnpj(correspondencia.group(0))


def _somente_em_contexto_pix(
    correspondencia: re.Match[str],
    texto: str,
) -> bool:
    del correspondencia
    return _tem_contexto_pix(texto)


REGRAS_BRASIL = (
    Regra(
        codigo="pix-email",
        tipo="Chave PIX por e-mail",
        padrao=re.compile(
            r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
            r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w.-])"
        ),
        validador=_somente_em_contexto_pix,
        severidade="medio",
    ),
    Regra(
        codigo="pix-evp",
        tipo="Chave PIX EVP",
        padrao=re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
            re.IGNORECASE,
        ),
        validador=_somente_em_contexto_pix,
        severidade="medio",
    ),
    Regra(
        codigo="pix-cpf",
        tipo="Chave PIX por CPF",
        padrao=_CPF,
        validador=_cpf_pix,
        severidade="medio",
    ),
    Regra(
        codigo="pix-cnpj",
        tipo="Chave PIX por CNPJ",
        padrao=_CNPJ,
        validador=_cnpj_pix,
        severidade="medio",
    ),
    Regra(
        codigo="cpf-hardcoded",
        tipo="CPF hardcoded em massa",
        padrao=_CPF,
        validador=_cpf_hardcoded,
        minimo_por_arquivo=5,
        severidade="medio",
    ),
    Regra(
        codigo="cnpj-hardcoded",
        tipo="CNPJ hardcoded em massa",
        padrao=_CNPJ,
        validador=_cnpj_hardcoded,
        minimo_por_arquivo=5,
        severidade="medio",
    ),
)
