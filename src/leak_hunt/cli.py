"""Interface de linha de comando do leak-hunt."""

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys

from leak_hunt.regras import detectar
from leak_hunt.varredura import (
    ErroRepositorio,
    ErroVarredura,
    iterar_linhas_adicionadas,
    validar_repositorio,
)
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

    try:
        repositorio = validar_repositorio(argumentos.caminho)
    except ErroRepositorio as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2

    try:
        total_linhas = 0
        total_segredos = 0
        for linha in iterar_linhas_adicionadas(repositorio):
            total_linhas += 1
            total_segredos += sum(1 for _ in detectar(linha.conteudo))
    except ErroVarredura as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2

    descricao = (
        "linha adicionada analisada"
        if total_linhas == 1
        else "linhas adicionadas analisadas"
    )
    descricao_segredos = (
        "possível segredo" if total_segredos == 1 else "possíveis segredos"
    )
    print(
        f"Varredura concluída: {total_linhas} {descricao}; "
        f"{total_segredos} {descricao_segredos}."
    )
    return 0
