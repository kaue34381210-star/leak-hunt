"""Regras aplicadas a blobs de arquivos sensíveis."""

import re

from leak_hunt.regras.base import Regra


_NUNCA_CORRESPONDE = re.compile(r"(?!)")


REGRAS_ARQUIVOS = (
    Regra(
        codigo="pkcs12-file",
        tipo="Contêiner PKCS#12 versionado",
        padrao=_NUNCA_CORRESPONDE,
        severidade="critico",
    ),
    Regra(
        codigo="jks-keystore",
        tipo="Java KeyStore versionado",
        padrao=_NUNCA_CORRESPONDE,
        severidade="critico",
    ),
    Regra(
        codigo="private-key-file",
        tipo="Arquivo de chave privada versionado",
        padrao=_NUNCA_CORRESPONDE,
        severidade="critico",
    ),
)
