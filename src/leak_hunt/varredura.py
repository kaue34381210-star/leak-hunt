"""Acesso local aos repositórios Git analisados pelo leak-hunt."""

import ast
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import date, datetime
import re
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from leak_hunt.exclusoes import caminho_excluido


_SEPARADOR_COMMIT = "\x1e"
_SEPARADOR_CAMPO = "\x1f"
_CABECALHO_TRECHO = re.compile(
    r"^@@ -\d+(?:,\d+)? \+(?P<linha>\d+)(?:,\d+)? @@"
)
_EXTENSOES_BLOB = frozenset(
    {".p12", ".pfx", ".jks", ".keystore", ".key"}
)
_LIMITE_BLOB = 10 * 1024 * 1024


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


@dataclass(frozen=True, slots=True)
class BlobSuspeito:
    """Arquivo sensível identificado por conteúdo e extensão."""

    commit: str
    autor: str
    data: str
    arquivo: str
    oid: str
    codigo: str
    tipo: str


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
        try:
            decodificado = ast.literal_eval(valor)
        except (SyntaxError, ValueError):
            decodificado = valor[1:-1]
        if isinstance(decodificado, str):
            valor = decodificado
    if valor.startswith("b/"):
        valor = valor[2:]
    return valor


def _interpretar_patch(
    linhas: Iterable[str],
    exclusoes: Sequence[str],
    commit: str = "",
    autor: str = "",
    data: str = "",
) -> Iterator[LinhaAdicionada]:
    """Converte um patch Git textual em linhas adicionadas."""
    arquivo: str | None = None
    numero: int | None = None

    for linha_bruta in linhas:
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


def _executar_patch(
    comando: Sequence[str],
    exclusoes: Sequence[str],
    origem: str,
    commit: str = "",
    autor: str = "",
    data: str = "",
) -> Iterator[LinhaAdicionada]:
    """Executa um comando Git e interpreta seu patch em streaming."""
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

        assert processo.stdout is not None
        try:
            yield from _interpretar_patch(
                processo.stdout,
                exclusoes,
                commit=commit,
                autor=autor,
                data=data,
            )
            retorno = processo.wait()
            if retorno != 0:
                erros.seek(0)
                detalhe = erros.read().strip() or "erro desconhecido do Git"
                raise ErroVarredura(f"não foi possível ler {origem}: {detalhe}")
        finally:
            processo.stdout.close()
            if processo.poll() is None:
                processo.terminate()
                try:
                    processo.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    processo.kill()
                    processo.wait()


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

    yield from _executar_patch(comando, exclusoes, "o histórico")


def iterar_linhas_staged(
    caminho: Path,
    exclusoes: Sequence[str] = (),
) -> Iterator[LinhaAdicionada]:
    """Percorre as linhas adicionadas atualmente no index do Git."""
    repositorio = validar_repositorio(caminho)
    comando = [
        "git",
        "-c",
        "core.quotePath=false",
        "-C",
        str(repositorio),
        "diff",
        "--cached",
        "--patch",
        "--no-ext-diff",
        "--no-renames",
        "--unified=0",
    ]
    data = datetime.now().astimezone().isoformat(timespec="seconds")
    yield from _executar_patch(
        comando,
        exclusoes,
        "o index",
        commit="INDEX",
        autor="(ainda não commitado)",
        data=data,
    )


def _sequencia_der_completa(conteudo: bytes) -> bool:
    """Valida o envelope e o comprimento de uma sequência DER superior."""
    if len(conteudo) < 2 or conteudo[0] != 0x30:
        return False
    primeiro_comprimento = conteudo[1]
    if primeiro_comprimento < 0x80:
        tamanho_cabecalho = 2
        tamanho_conteudo = primeiro_comprimento
    else:
        bytes_comprimento = primeiro_comprimento & 0x7F
        if bytes_comprimento == 0 or bytes_comprimento > 4:
            return False
        fim_comprimento = 2 + bytes_comprimento
        if len(conteudo) < fim_comprimento:
            return False
        tamanho_cabecalho = fim_comprimento
        tamanho_conteudo = int.from_bytes(conteudo[2:fim_comprimento], "big")
    return tamanho_cabecalho + tamanho_conteudo == len(conteudo)


def _classificar_blob(arquivo: str, conteudo: bytes) -> tuple[str, str] | None:
    extensao = PurePosixPath(arquivo).suffix.lower()
    if extensao in {".p12", ".pfx"} and _sequencia_der_completa(conteudo):
        return "pkcs12-file", "Contêiner PKCS#12 versionado"
    if extensao in {".jks", ".keystore"} and conteudo.startswith(
        b"\xfe\xed\xfe\xed"
    ):
        return "jks-keystore", "Java KeyStore versionado"
    if extensao == ".key" and _sequencia_der_completa(conteudo):
        return "private-key-file", "Arquivo de chave privada versionado"
    return None


def _ler_blob(repositorio: Path, oid: str) -> bytes | None:
    """Lê um blob candidato com limite de tamanho para proteger a memória."""
    comando_base = ["git", "-C", str(repositorio), "cat-file"]
    try:
        tamanho = subprocess.run(
            [*comando_base, "-s", oid],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as erro:
        raise ErroVarredura(f"não foi possível inspecionar o blob {oid}") from erro
    if tamanho.returncode != 0:
        detalhe = tamanho.stderr.strip() or "objeto Git inválido"
        raise ErroVarredura(f"não foi possível inspecionar o blob {oid}: {detalhe}")
    try:
        quantidade = int(tamanho.stdout.strip())
    except ValueError as erro:
        raise ErroVarredura(f"tamanho inválido para o blob {oid}") from erro
    if quantidade > _LIMITE_BLOB:
        return None

    try:
        resultado = subprocess.run(
            [*comando_base, "blob", oid],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as erro:
        raise ErroVarredura(f"não foi possível ler o blob {oid}") from erro
    if resultado.returncode != 0:
        detalhe = resultado.stderr.decode("utf-8", errors="replace").strip()
        raise ErroVarredura(
            f"não foi possível ler o blob {oid}: {detalhe or 'erro do Git'}"
        )
    return resultado.stdout


def _iterar_blobs_do_comando(
    repositorio: Path,
    comando: Sequence[str],
    exclusoes: Sequence[str],
    origem: str,
    commit: str = "",
    autor: str = "",
    data: str = "",
) -> Iterator[BlobSuspeito]:
    cache: dict[tuple[str, str], tuple[str, str] | None] = {}
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

        assert processo.stdout is not None
        try:
            for linha_bruta in processo.stdout:
                linha = linha_bruta.rstrip("\n")
                if linha.startswith(_SEPARADOR_COMMIT):
                    campos = linha[1:].split(_SEPARADOR_CAMPO, maxsplit=2)
                    if len(campos) == 3:
                        commit, autor, data = campos
                    continue
                if not linha.startswith(":") or "\t" not in linha:
                    continue
                metadados, caminho_git = linha.split("\t", maxsplit=1)
                campos = metadados.split()
                if len(campos) < 5:
                    continue
                oid = campos[3]
                arquivo = _caminho_do_diff(caminho_git)
                if arquivo is None or caminho_excluido(arquivo, exclusoes):
                    continue
                extensao = PurePosixPath(arquivo).suffix.lower()
                if extensao not in _EXTENSOES_BLOB:
                    continue
                chave_cache = (oid, extensao)
                if chave_cache not in cache:
                    conteudo = _ler_blob(repositorio, oid)
                    cache[chave_cache] = (
                        _classificar_blob(arquivo, conteudo)
                        if conteudo is not None
                        else None
                    )
                classificacao = cache[chave_cache]
                if classificacao is None:
                    continue
                codigo, tipo = classificacao
                yield BlobSuspeito(
                    commit=commit,
                    autor=autor,
                    data=data,
                    arquivo=arquivo,
                    oid=oid,
                    codigo=codigo,
                    tipo=tipo,
                )

            retorno = processo.wait()
            if retorno != 0:
                erros.seek(0)
                detalhe = erros.read().strip() or "erro desconhecido do Git"
                raise ErroVarredura(f"não foi possível ler {origem}: {detalhe}")
        finally:
            processo.stdout.close()
            if processo.poll() is None:
                processo.terminate()
                try:
                    processo.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    processo.kill()
                    processo.wait()


def iterar_blobs_sensiveis(
    caminho: Path,
    desde: date | None = None,
    exclusoes: Sequence[str] = (),
    refs: str = "all",
) -> Iterator[BlobSuspeito]:
    """Percorre blobs de formatos sensíveis presentes no histórico Git."""
    repositorio = validar_repositorio(caminho)
    comando = [
        "git",
        "-c",
        "core.quotePath=false",
        "-C",
        str(repositorio),
        "log",
        "--raw",
        "--full-history",
        "--root",
        "--no-renames",
        "--no-abbrev",
        "--diff-filter=AM",
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
    yield from _iterar_blobs_do_comando(
        repositorio,
        comando,
        exclusoes,
        "os blobs do histórico",
    )


def iterar_blobs_staged(
    caminho: Path,
    exclusoes: Sequence[str] = (),
) -> Iterator[BlobSuspeito]:
    """Percorre blobs de formatos sensíveis presentes no index do Git."""
    repositorio = validar_repositorio(caminho)
    comando = [
        "git",
        "-c",
        "core.quotePath=false",
        "-C",
        str(repositorio),
        "diff",
        "--cached",
        "--raw",
        "--no-renames",
        "--no-abbrev",
        "--diff-filter=AM",
    ]
    data = datetime.now().astimezone().isoformat(timespec="seconds")
    yield from _iterar_blobs_do_comando(
        repositorio,
        comando,
        exclusoes,
        "os blobs do index",
        commit="INDEX",
        autor="(ainda não commitado)",
        data=data,
    )
