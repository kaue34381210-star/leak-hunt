"""Registro público das regras de detecção do leak-hunt."""

from collections.abc import Iterable, Iterator

from leak_hunt.regras.base import Deteccao, Regra
from leak_hunt.regras.brasil import REGRAS_BRASIL
from leak_hunt.regras.genericos import REGRAS_GENERICAS


REGRAS: tuple[Regra, ...] = REGRAS_GENERICAS + REGRAS_BRASIL


class ErroSelecaoRegras(ValueError):
    """Indica códigos de regra inexistentes fornecidos pela CLI."""


def selecionar_regras(
    somente: Iterable[str] = (),
    ignorar: Iterable[str] = (),
) -> tuple[Regra, ...]:
    """Seleciona regras por código, validando todos os nomes recebidos."""
    somente_set = set(somente)
    ignorar_set = set(ignorar)
    disponiveis = {regra.codigo for regra in REGRAS}
    desconhecidos = (somente_set | ignorar_set) - disponiveis
    if desconhecidos:
        lista = ", ".join(sorted(desconhecidos))
        raise ErroSelecaoRegras(f"código de regra desconhecido: {lista}")

    selecionadas = REGRAS
    if somente_set:
        selecionadas = tuple(
            regra for regra in selecionadas if regra.codigo in somente_set
        )
    return tuple(regra for regra in selecionadas if regra.codigo not in ignorar_set)


def detectar(
    texto: str,
    regras: Iterable[Regra] = REGRAS,
) -> Iterator[Deteccao]:
    """Aplica todas as regras registradas a uma linha de texto."""
    for regra in regras:
        yield from regra.procurar(texto)


__all__ = [
    "Deteccao",
    "ErroSelecaoRegras",
    "REGRAS",
    "Regra",
    "detectar",
    "selecionar_regras",
]
