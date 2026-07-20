"""Acesso local aos repositórios Git analisados pelo leak-hunt."""

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import date
import re
import subprocess
import tempfile
from pathlib import Path

from leak_hunt.exclusoes import caminho_excluido


_SEPARADOR_COMMIT = "\x1e"
_SEPARADOR_CAMPO = "\x1f"
_CABECALHO_TRECHO = re.compile(
    r"^@@ -\d+(?:,\d+)? \+(?P<linha>\d+)(?:,\d+)? @@"
)


class ErroRepositorio(Exception):
    """Indica que o caminho informado não pode ser analisado como Git."""


class ErroVarredura(Exception):
    """Indica uma falha do Git durante a leitura do histórico."""


@dataclass(frozen=True, slots=True)
class LinhaAdicionada:
    """Linha acrescentada por um commit do histórico."""

    commit: str
    autor: str
    data: str
    arquivo: str
    numero: int
    conteudo: str


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


def _caminho_do_diff(valor: str) -> str | None:
    """Converte o caminho exibido pelo patch para o caminho do repositório."""
    if valor == "/dev/null":
        return None
    if valor.startswith('"') and valor.endswith('"'):
        valor = valor[1:-1]
    if valor.startswith("b/"):
        valor = valor[2:]
    return valor


def iterar_linhas_adicionadas(
    caminho: Path,
    desde: date | None = None,
    exclusoes: Sequence[str] = (),
    refs: str = "all",
) -> Iterator[LinhaAdicionada]:
    """Percorre em fluxo todas as linhas adicionadas no histórico Git."""
    repositorio = validar_repositorio(caminho)
    comando = [
        "git",
        "-c",
        "core.quotePath=false",
        "-C",
        str(repositorio),
        "log",
        "--patch",
        "--full-history",
        "--no-ext-diff",
        "--no-renames",
        "--unified=0",
    ]
    if desde is not None:
        comando.append(f"--since={desde.isoformat()}")
    comando.append(
        f"--format={_SEPARADOR_COMMIT}%H{_SEPARADOR_CAMPO}%an{_SEPARADOR_CAMPO}%aI"
    )
    if refs == "all":
        comando.append("--all")
    elif refs == "head":
        comando.append("HEAD")
    elif refs == "branches":
        comando.append("--branches")
    else:
        raise ErroVarredura(f"escopo de referências inválido: {refs}")

    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as erros:
        try:
            processo = subprocess.Popen(
                comando,
                stdout=subprocess.PIPE,
                stderr=erros,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as erro:
            raise ErroVarredura("o executável git não foi encontrado") from erro

        commit = ""
        autor = ""
        data = ""
        arquivo: str | None = None
        numero: int | None = None

        assert processo.stdout is not None
        try:
            for linha_bruta in processo.stdout:
                linha = linha_bruta.rstrip("\n")

                if linha.startswith(_SEPARADOR_COMMIT):
                    campos = linha[1:].split(_SEPARADOR_CAMPO, maxsplit=2)
                    if len(campos) == 3:
                        commit, autor, data = campos
                    arquivo = None
                    numero = None
                    continue

                if linha.startswith("diff --git "):
                    arquivo = None
                    numero = None
                    continue

                if numero is None and linha.startswith("+++ "):
                    arquivo = _caminho_do_diff(linha[4:])
                    continue

                cabecalho = _CABECALHO_TRECHO.match(linha)
                if cabecalho:
                    numero = int(cabecalho.group("linha"))
                    continue

                if arquivo is None or numero is None:
                    continue

                if linha.startswith("+"):
                    if not caminho_excluido(arquivo, exclusoes):
                        yield LinhaAdicionada(
                            commit=commit,
                            autor=autor,
                            data=data,
                            arquivo=arquivo,
                            numero=numero,
                            conteudo=linha[1:],
                        )
                    numero += 1
                elif not linha.startswith(("-", "\\")):
                    numero += 1

            retorno = processo.wait()
            if retorno != 0:
                erros.seek(0)
                detalhe = erros.read().strip() or "erro desconhecido do Git"
                raise ErroVarredura(f"não foi possível ler o histórico: {detalhe}")
        finally:
            processo.stdout.close()
            if processo.poll() is None:
                processo.terminate()
                try:
                    processo.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    processo.kill()
                    processo.wait()
