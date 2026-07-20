"""Interface de linha de comando do leak-hunt."""

import argparse
from collections.abc import Sequence
from datetime import date
from pathlib import Path
import sys

from leak_hunt.regras import detectar
from leak_hunt.relatorio import (
    Achado,
    criar_achado,
    filtrar_por_limiar,
    formatar_json,
    formatar_texto,
)
from leak_hunt.varredura import (
    ErroRepositorio,
    ErroVarredura,
    iterar_linhas_adicionadas,
    validar_repositorio,
)
from leak_hunt.versao import __version__


def _data_iso(valor: str) -> date:
    try:
        return date.fromisoformat(valor)
    except ValueError as erro:
        raise argparse.ArgumentTypeError(
            "a data deve estar no formato AAAA-MM-DD"
        ) from erro


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
        "--since",
        dest="desde",
        metavar="DATA",
        type=_data_iso,
        help="analisa apenas commits desde DATA (AAAA-MM-DD)",
    )
    parser.add_argument(
        "--format",
        dest="formato",
        choices=("text", "json"),
        default="text",
        help="formato do relatório (padrão: text)",
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
        achados: list[Achado] = []
        for linha in iterar_linhas_adicionadas(
            repositorio,
            desde=argumentos.desde,
        ):
            total_linhas += 1
            achados.extend(
                criar_achado(linha, deteccao)
                for deteccao in detectar(linha.conteudo)
            )
    except ErroVarredura as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2

    achados = filtrar_por_limiar(achados)
    if argumentos.formato == "json":
        relatorio = formatar_json(achados, total_linhas, repositorio)
    else:
        relatorio = formatar_texto(achados, total_linhas)
    print(relatorio)
    return 1 if achados else 0
