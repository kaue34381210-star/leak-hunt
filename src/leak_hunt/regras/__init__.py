"""Registro público das regras de detecção do leak-hunt."""

from collections.abc import Iterable, Iterator

from leak_hunt.regras.base import Deteccao, Regra
from leak_hunt.regras.brasil import REGRAS_BRASIL
from leak_hunt.regras.genericos import REGRAS_GENERICAS


REGRAS: tuple[Regra, ...] = REGRAS_GENERICAS + REGRAS_BRASIL


def detectar(
    texto: str,
    regras: Iterable[Regra] = REGRAS,
) -> Iterator[Deteccao]:
    """Aplica todas as regras registradas a uma linha de texto."""
    for regra in regras:
        yield from regra.procurar(texto)


__all__ = ["Deteccao", "REGRAS", "Regra", "detectar"]
