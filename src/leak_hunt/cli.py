"""Interface de linha de comando do leak-hunt."""

import argparse
from collections.abc import Sequence
from datetime import date
from pathlib import Path
import sys

from leak_hunt.exclusoes import carregar_exclusoes
from leak_hunt.regras import ErroSelecaoRegras, detectar, selecionar_regras
from leak_hunt.relatorio import (
    AgregadorAchados,
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
        "--refs",
        choices=("all", "head", "branches"),
        default="all",
        help="referências Git analisadas (padrão: all)",
    )
    parser.add_argument(
        "--exclude",
        dest="exclusoes",
        action="append",
        default=[],
        metavar="GLOB",
        help="ignora caminhos que casem com GLOB; pode ser repetido",
    )
    parser.add_argument(
        "--only",
        dest="somente_regras",
        action="append",
        default=[],
        metavar="CODE",
        help="executa somente a regra CODE; pode ser repetido",
    )
    parser.add_argument(
        "--skip",
        dest="ignorar_regras",
        action="append",
        default=[],
        metavar="CODE",
        help="desativa a regra CODE; pode ser repetido",
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
        regras = selecionar_regras(
            somente=argumentos.somente_regras,
            ignorar=argumentos.ignorar_regras,
        )
    except ErroSelecaoRegras as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2

    try:
        repositorio = validar_repositorio(argumentos.caminho)
    except ErroRepositorio as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2

    try:
        total_linhas = 0
        agregador = AgregadorAchados()
        exclusoes = carregar_exclusoes(repositorio, argumentos.exclusoes)
        for linha in iterar_linhas_adicionadas(
            repositorio,
            desde=argumentos.desde,
            exclusoes=exclusoes,
            refs=argumentos.refs,
        ):
            total_linhas += 1
            for deteccao in detectar(linha.conteudo, regras=regras):
                agregador.adicionar(linha, deteccao)
    except ErroVarredura as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2

    achados = agregador.finalizar()
    if argumentos.formato == "json":
        relatorio = formatar_json(achados, total_linhas, repositorio)
    else:
        relatorio = formatar_texto(achados, total_linhas)
    print(relatorio)
    return 1 if achados else 0
