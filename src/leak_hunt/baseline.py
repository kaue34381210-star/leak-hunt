"""Persistência segura da baseline de achados aceitos."""

import hashlib
import json
from pathlib import Path
import re
import tempfile


ARQUIVO_BASELINE = ".leakhuntbaseline.json"
VERSAO_BASELINE = 1
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")


class ErroBaseline(Exception):
    """Indica que a baseline não pôde ser lida ou escrita."""


def criar_fingerprint(codigo: str, valor: str, arquivo: str) -> str:
    """Cria um identificador versionado sem persistir o valor detectado."""
    hash_ = hashlib.sha256()
    for parte in ("leak-hunt-baseline-v1", codigo, arquivo, valor):
        hash_.update(parte.encode("utf-8", errors="surrogatepass"))
        hash_.update(b"\0")
    return hash_.hexdigest()


def carregar_baseline(repositorio: Path) -> frozenset[str]:
    """Carrega e valida a baseline do repositório, quando presente."""
    caminho = repositorio / ARQUIVO_BASELINE
    if not caminho.exists():
        return frozenset()

    try:
        documento = json.loads(caminho.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as erro:
        raise ErroBaseline(f"não foi possível ler {caminho}: {erro}") from erro

    if (
        not isinstance(documento, dict)
        or documento.get("versao_schema") != VERSAO_BASELINE
    ):
        raise ErroBaseline(f"schema de baseline inválido: {caminho}")
    fingerprints = documento.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(
        isinstance(item, str) and _FINGERPRINT.fullmatch(item)
        for item in fingerprints
    ):
        raise ErroBaseline(f"lista de fingerprints inválida: {caminho}")
    return frozenset(fingerprints)


def salvar_baseline(repositorio: Path, fingerprints: set[str]) -> Path:
    """Substitui a baseline de forma atômica e devolve seu caminho."""
    caminho = repositorio / ARQUIVO_BASELINE
    documento = {
        "versao_schema": VERSAO_BASELINE,
        "algoritmo": "sha256",
        "fingerprints": sorted(fingerprints),
    }
    temporario: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=repositorio,
            prefix=f"{ARQUIVO_BASELINE}.",
            delete=False,
        ) as arquivo:
            temporario = Path(arquivo.name)
            json.dump(documento, arquivo, ensure_ascii=False, indent=2)
            arquivo.write("\n")
        temporario.replace(caminho)
    except OSError as erro:
        if temporario is not None:
            temporario.unlink(missing_ok=True)
        raise ErroBaseline(f"não foi possível escrever {caminho}: {erro}") from erro
    return caminho
