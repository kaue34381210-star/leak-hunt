"""Interface de linha de comando do leak-hunt."""

import argparse
from collections.abc import Sequence
from pathlib import Path

from leak_hunt.versao import __version__


def criar_parser() -> argparse.ArgumentParser:
    """Cria o parser da interface de linha de comando."""
    parser = argparse.ArgumentParser(
        prog="leak-hunt",
        description="Procura segredos no historico de repositorios Git.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "caminho",
        metavar="CAMINHO",
        nargs="?",
        type=Path,
        help="caminho do repositório Git que será analisado",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Executa a interface de linha de comando."""
    parser = criar_parser()
    argumentos = parser.parse_args(argv)
    if argumentos.caminho is None:
        parser.print_help()
        return 0

    print(f"Repositório selecionado: {argumentos.caminho}")
    return 0
