"""Interface de linha de comando do leak-hunt."""

import argparse
from collections.abc import Sequence
from datetime import date
from pathlib import Path
import sys
from typing import cast

from leak_hunt.baseline import ErroBaseline, carregar_baseline, salvar_baseline
from leak_hunt.exclusoes import carregar_exclusoes
from leak_hunt.regras import (
    ErroSelecaoRegras,
    SEVERIDADES,
    Deteccao,
    Severidade,
    detectar,
    selecionar_regras,
)
from leak_hunt.relatorio import (
    AgregadorAchados,
    formatar_json,
    formatar_sarif,
    formatar_texto,
)
from leak_hunt.varredura import (
    ErroRepositorio,
    ErroVarredura,
    LinhaAdicionada,
    iterar_blobs_sensiveis,
    iterar_blobs_staged,
    iterar_linhas_adicionadas,
    iterar_linhas_staged,
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


def _lista_severidades(valor: str) -> frozenset[Severidade]:
    niveis = {item.strip().lower() for item in valor.split(",") if item.strip()}
    desconhecidos = niveis - set(SEVERIDADES)
    if not niveis or desconhecidos:
        validos = ", ".join(SEVERIDADES)
        raise argparse.ArgumentTypeError(
            f"severidade inválida; use uma ou mais entre: {validos}"
        )
    return frozenset(cast(Severidade, nivel) for nivel in niveis)


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
        choices=("text", "json", "sarif"),
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
        "--staged",
        action="store_true",
        help="analisa somente as linhas adicionadas no index do Git",
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
        "--fail-on",
        dest="falhar_em",
        metavar="NIVEL[,NIVEL]",
        type=_lista_severidades,
        help=(
            "retorna 1 somente para achados nos níveis selecionados "
            "(critico, alto, medio, baixo)"
        ),
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="substitui a baseline pelos achados atuais e retorna 0",
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
    if argumentos.staged and argumentos.desde is not None:
        parser.error("--staged não pode ser combinado com --since")
    if argumentos.staged and argumentos.refs != "all":
        parser.error("--staged não pode ser combinado com --refs")
    if argumentos.update_baseline and (
        argumentos.staged
        or argumentos.desde is not None
        or argumentos.refs != "all"
        or argumentos.somente_regras
        or argumentos.ignorar_regras
        or argumentos.exclusoes
    ):
        parser.error(
            "--update-baseline exige a varredura completa, sem filtros da CLI"
        )

    caminho = argumentos.caminho
    if caminho is None and argumentos.staged:
        caminho = Path(".")
    if caminho is None:
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
        repositorio = validar_repositorio(caminho)
    except ErroRepositorio as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2

    try:
        total_linhas = 0
        fingerprints_ignorados = (
            frozenset()
            if argumentos.update_baseline
            else carregar_baseline(repositorio)
        )
        agregador = AgregadorAchados(fingerprints_ignorados)
        exclusoes = carregar_exclusoes(repositorio, argumentos.exclusoes)
        regras_por_codigo = {regra.codigo: regra for regra in regras}
        if argumentos.staged:
            linhas = iterar_linhas_staged(repositorio, exclusoes=exclusoes)
        else:
            linhas = iterar_linhas_adicionadas(
                repositorio,
                desde=argumentos.desde,
                exclusoes=exclusoes,
                refs=argumentos.refs,
            )
        for linha in linhas:
            total_linhas += 1
            for deteccao in detectar(
                linha.conteudo,
                regras=regras,
                arquivo=linha.arquivo,
            ):
                agregador.adicionar(linha, deteccao)

        if argumentos.staged:
            blobs = iterar_blobs_staged(repositorio, exclusoes=exclusoes)
        else:
            blobs = iterar_blobs_sensiveis(
                repositorio,
                desde=argumentos.desde,
                exclusoes=exclusoes,
                refs=argumentos.refs,
            )
        for blob in blobs:
            regra = regras_por_codigo.get(blob.codigo)
            if regra is None:
                continue
            linha_blob = LinhaAdicionada(
                commit=blob.commit,
                autor=blob.autor,
                data=blob.data,
                arquivo=blob.arquivo,
                numero=1,
                conteudo="",
            )
            agregador.adicionar(
                linha_blob,
                Deteccao(
                    codigo=regra.codigo,
                    tipo=regra.tipo,
                    valor=blob.oid,
                    inicio=0,
                    fim=len(blob.oid),
                    severidade=regra.severidade,
                ),
            )
    except (ErroBaseline, ErroVarredura) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2

    achados = agregador.finalizar()
    if argumentos.update_baseline:
        fingerprints = agregador.fingerprints()
        try:
            caminho_baseline = salvar_baseline(
                repositorio,
                fingerprints,
            )
        except ErroBaseline as erro:
            print(f"erro: {erro}", file=sys.stderr)
            return 2
        print(
            f"Baseline atualizada: {caminho_baseline} "
            f"({len(fingerprints)} fingerprints)",
            file=sys.stderr,
        )
    if argumentos.formato == "json":
        relatorio = formatar_json(achados, total_linhas, repositorio)
    elif argumentos.formato == "sarif":
        relatorio = formatar_sarif(achados)
    else:
        relatorio = formatar_texto(achados, total_linhas)
    print(relatorio)
    if argumentos.update_baseline:
        return 0
    if argumentos.falhar_em is None:
        return 1 if achados else 0
    return int(
        any(achado.severidade in argumentos.falhar_em for achado in achados)
    )
