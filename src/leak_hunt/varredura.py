"""Acesso local aos repositórios Git analisados pelo leak-hunt."""

import subprocess
from pathlib import Path


class ErroRepositorio(Exception):
    """Indica que o caminho informado não pode ser analisado como Git."""


def validar_repositorio(caminho: Path) -> Path:
    """Valida o caminho e devolve sua forma absoluta."""
    repositorio = caminho.expanduser().resolve()
    if not repositorio.exists():
        raise ErroRepositorio(f"o caminho não existe: {repositorio}")
    if not repositorio.is_dir():
        raise ErroRepositorio(f"o caminho não é um diretório: {repositorio}")

    try:
        resultado = subprocess.run(
            ["git", "-C", str(repositorio), "rev-parse", "--git-dir"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except FileNotFoundError as erro:
        raise ErroRepositorio("o executável git não foi encontrado") from erro
    except subprocess.TimeoutExpired as erro:
        raise ErroRepositorio("o Git demorou demais para validar o caminho") from erro

    if resultado.returncode != 0:
        raise ErroRepositorio(f"o caminho não é um repositório Git: {repositorio}")

    return repositorio
