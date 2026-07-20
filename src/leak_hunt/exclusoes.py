"""Carregamento e aplicação de exclusões por caminho."""

from collections.abc import Iterable
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath


ARQUIVO_EXCLUSOES = ".leakhuntignore"


def carregar_exclusoes(
    repositorio: Path,
    adicionais: Iterable[str] = (),
) -> tuple[str, ...]:
    """Combina padrões do repositório com os fornecidos pela CLI."""
    padroes: list[str] = []
    arquivo = repositorio / ARQUIVO_EXCLUSOES
    if arquivo.is_file():
        for linha in arquivo.read_text(encoding="utf-8", errors="replace").splitlines():
            padrao = linha.strip()
            if padrao and not padrao.startswith("#"):
                padroes.append(padrao)
    padroes.extend(padrao for padrao in adicionais if padrao.strip())
    return tuple(padroes)


def _corresponde(caminho: str, padrao: str) -> bool:
    caminho = caminho.removeprefix("./")
    ancorado = padrao.startswith("/")
    padrao = padrao.removeprefix("/")

    if padrao.endswith("/"):
        diretorio = padrao.rstrip("/")
        if ancorado:
            return caminho == diretorio or caminho.startswith(f"{diretorio}/")
        caminho_cercado = f"/{caminho}/"
        return (
            caminho == diretorio
            or caminho.startswith(f"{diretorio}/")
            or f"/{diretorio}/" in caminho_cercado
        )

    if "/" not in padrao:
        return any(fnmatchcase(parte, padrao) for parte in caminho.split("/"))

    if fnmatchcase(caminho, padrao) or PurePosixPath(caminho).match(padrao):
        return True
    if not ancorado and padrao.startswith("**/"):
        return fnmatchcase(caminho, padrao[3:])
    return False


def caminho_excluido(caminho: str, padroes: Iterable[str]) -> bool:
    """Aplica globs em ordem, com ``!`` para reincluir um caminho."""
    excluido = False
    for padrao_bruto in padroes:
        padrao = padrao_bruto.strip()
        if not padrao or padrao.startswith("#"):
            continue
        reincluir = padrao.startswith("!")
        if reincluir:
            padrao = padrao[1:]
        if padrao and _corresponde(caminho, padrao):
            excluido = not reincluir
    return excluido
