"""Modelos e formatação dos resultados da varredura."""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
from urllib.parse import quote

from leak_hunt.baseline import criar_fingerprint
from leak_hunt.regras import Deteccao, Severidade
from leak_hunt.varredura import LinhaAdicionada
from leak_hunt.versao import __version__


_NIVEL_SARIF: dict[Severidade, str] = {
    "critico": "error",
    "alto": "error",
    "medio": "warning",
    "baixo": "note",
}
_PONTUACAO_SEGURANCA: dict[Severidade, str] = {
    "critico": "9.5",
    "alto": "8.0",
    "medio": "5.5",
    "baixo": "3.0",
}


@dataclass(frozen=True, slots=True)
class Achado:
    """Segredo potencial associado à sua origem no histórico."""

    codigo: str
    tipo: str
    commit: str
    autor: str
    data: str
    arquivo: str
    linha: int
    trecho_ofuscado: str
    minimo_por_arquivo: int = 1
    ocorrencias: int = 1
    arquivos_afetados: tuple[str, ...] = ()
    primeiro_commit: str = ""
    commit_mais_recente: str = ""
    severidade: Severidade = "alto"


@dataclass(slots=True)
class _GrupoAchados:
    codigo: str
    tipo: str
    severidade: Severidade
    trecho_ofuscado: str
    minimo_por_arquivo: int
    ocorrencias: int
    por_arquivo: Counter[str]
    primeira_linha: LinhaAdicionada
    linha_mais_recente: LinhaAdicionada
    fingerprints: set[str]


class AgregadorAchados:
    """Deduplica ocorrências sem manter o valor bruto ou cada ocorrência."""

    def __init__(
        self,
        fingerprints_ignorados: frozenset[str] = frozenset(),
    ) -> None:
        self._grupos: dict[tuple[str, bytes], _GrupoAchados] = {}
        self._fingerprints_ignorados = fingerprints_ignorados

    def adicionar(self, linha: LinhaAdicionada, deteccao: Deteccao) -> None:
        """Acrescenta uma ocorrência ao grupo do mesmo segredo e regra."""
        fingerprint = criar_fingerprint(
            deteccao.codigo,
            deteccao.valor,
            linha.arquivo,
        )
        if fingerprint in self._fingerprints_ignorados:
            return
        resumo = hashlib.sha256(
            deteccao.valor.encode("utf-8", errors="surrogatepass")
        ).digest()
        chave = (deteccao.codigo, resumo)
        grupo = self._grupos.get(chave)
        if grupo is None:
            self._grupos[chave] = _GrupoAchados(
                codigo=deteccao.codigo,
                tipo=deteccao.tipo,
                severidade=deteccao.severidade,
                trecho_ofuscado=ofuscar(deteccao.valor),
                minimo_por_arquivo=deteccao.minimo_por_arquivo,
                ocorrencias=1,
                por_arquivo=Counter({linha.arquivo: 1}),
                primeira_linha=linha,
                linha_mais_recente=linha,
                fingerprints={fingerprint},
            )
            return

        grupo.ocorrencias += 1
        grupo.por_arquivo[linha.arquivo] += 1
        grupo.fingerprints.add(fingerprint)
        if _instante(linha.data) < _instante(grupo.primeira_linha.data):
            grupo.primeira_linha = linha
        if _instante(linha.data) > _instante(grupo.linha_mais_recente.data):
            grupo.linha_mais_recente = linha

    def finalizar(self) -> list[Achado]:
        """Materializa apenas grupos que atingiram o limiar por arquivo."""
        achados: list[Achado] = []
        for grupo in self._grupos.values():
            if max(grupo.por_arquivo.values()) < grupo.minimo_por_arquivo:
                continue
            recente = grupo.linha_mais_recente
            achados.append(
                Achado(
                    codigo=grupo.codigo,
                    tipo=grupo.tipo,
                    severidade=grupo.severidade,
                    commit=recente.commit,
                    autor=recente.autor,
                    data=recente.data,
                    arquivo=recente.arquivo,
                    linha=recente.numero,
                    trecho_ofuscado=grupo.trecho_ofuscado,
                    minimo_por_arquivo=grupo.minimo_por_arquivo,
                    ocorrencias=grupo.ocorrencias,
                    arquivos_afetados=tuple(sorted(grupo.por_arquivo)),
                    primeiro_commit=grupo.primeira_linha.commit,
                    commit_mais_recente=recente.commit,
                )
            )
        return achados

    def fingerprints(self) -> set[str]:
        """Retorna fingerprints apenas dos grupos que virariam achados."""
        return {
            fingerprint
            for grupo in self._grupos.values()
            if max(grupo.por_arquivo.values()) >= grupo.minimo_por_arquivo
            for fingerprint in grupo.fingerprints
        }


def _instante(valor: str) -> datetime:
    return datetime.fromisoformat(valor)


def ofuscar(valor: str) -> str:
    """Oculta o valor encontrado, preservando apenas suas extremidades."""
    if len(valor) <= 8:
        return "*" * len(valor)
    quantidade_visivel = 4 if len(valor) >= 12 else 2
    return (
        f"{valor[:quantidade_visivel]}…"
        f"{valor[-quantidade_visivel:]}"
    )


def criar_achado(linha: LinhaAdicionada, deteccao: Deteccao) -> Achado:
    """Combina a detecção com os metadados históricos da linha."""
    return Achado(
        codigo=deteccao.codigo,
        tipo=deteccao.tipo,
        commit=linha.commit,
        autor=linha.autor,
        data=linha.data,
        arquivo=linha.arquivo,
        linha=linha.numero,
        trecho_ofuscado=ofuscar(deteccao.valor),
        minimo_por_arquivo=deteccao.minimo_por_arquivo,
        arquivos_afetados=(linha.arquivo,),
        primeiro_commit=linha.commit,
        commit_mais_recente=linha.commit,
        severidade=deteccao.severidade,
    )


def filtrar_por_limiar(achados: list[Achado]) -> list[Achado]:
    """Remove alertas que não atingiram o mínimo exigido no mesmo arquivo."""
    contagens = Counter((achado.codigo, achado.arquivo) for achado in achados)
    return [
        achado
        for achado in achados
        if contagens[(achado.codigo, achado.arquivo)]
        >= achado.minimo_por_arquivo
    ]


def formatar_texto(achados: list[Achado], total_linhas: int) -> str:
    """Formata um relatório legível sem expor os segredos encontrados."""
    if not achados:
        return (
            "Nenhum segredo encontrado.\n"
            f"Linhas adicionadas analisadas: {total_linhas}"
        )

    partes = [
        f"Possíveis segredos únicos encontrados: {len(achados)}",
        f"Total de ocorrências: {sum(achado.ocorrencias for achado in achados)}",
        f"Linhas adicionadas analisadas: {total_linhas}",
    ]
    for indice, achado in enumerate(achados, start=1):
        partes.extend(
            [
                "",
                f"[{indice}] {achado.tipo} ({achado.codigo})",
                f"    Severidade: {achado.severidade}",
                f"    Commit: {achado.commit}",
                f"    Autor: {achado.autor}",
                f"    Data: {achado.data}",
                f"    Local: {achado.arquivo}:{achado.linha}",
                f"    Ocorrências: {achado.ocorrencias}",
                f"    Arquivos afetados: {len(achado.arquivos_afetados) or 1}",
                f"    Primeiro commit: {achado.primeiro_commit or achado.commit}",
                f"    Commit mais recente: {achado.commit_mais_recente or achado.commit}",
                f"    Trecho: {achado.trecho_ofuscado}",
            ]
        )
    return "\n".join(partes)


def formatar_json(
    achados: list[Achado],
    total_linhas: int,
    repositorio: Path,
) -> str:
    """Formata o relatório no schema JSON público da versão 1."""
    documento = {
        "versao_schema": 1,
        "repositorio": str(repositorio),
        "resumo": {
            "linhas_adicionadas_analisadas": total_linhas,
            "total_achados": len(achados),
            "total_ocorrencias": sum(achado.ocorrencias for achado in achados),
        },
        "achados": [
            {
                "codigo": achado.codigo,
                "tipo": achado.tipo,
                "severidade": achado.severidade,
                "commit": achado.commit,
                "autor": achado.autor,
                "data": achado.data,
                "arquivo": achado.arquivo,
                "linha": achado.linha,
                "trecho_ofuscado": achado.trecho_ofuscado,
                "ocorrencias": achado.ocorrencias,
                "arquivos_afetados": list(
                    achado.arquivos_afetados or (achado.arquivo,)
                ),
                "primeiro_commit": achado.primeiro_commit or achado.commit,
                "commit_mais_recente": (
                    achado.commit_mais_recente or achado.commit
                ),
            }
            for achado in achados
        ],
    }
    return json.dumps(documento, ensure_ascii=False, indent=2)


def formatar_sarif(achados: list[Achado]) -> str:
    """Formata os achados no subconjunto SARIF 2.1.0 aceito pelo GitHub."""
    por_codigo = {achado.codigo: achado for achado in achados}
    codigos = sorted(por_codigo)
    indices = {codigo: indice for indice, codigo in enumerate(codigos)}
    regras = [
        {
            "id": codigo,
            "name": codigo,
            "shortDescription": {"text": por_codigo[codigo].tipo},
            "fullDescription": {
                "text": (
                    f"O leak-hunt encontrou um possível segredo do tipo "
                    f"{por_codigo[codigo].tipo}."
                )
            },
            "defaultConfiguration": {
                "level": _NIVEL_SARIF[por_codigo[codigo].severidade]
            },
            "help": {
                "text": "Remova o valor do histórico e revogue a credencial exposta."
            },
            "properties": {
                "tags": ["security", "secret"],
                "security-severity": _PONTUACAO_SEGURANCA[
                    por_codigo[codigo].severidade
                ],
            },
        }
        for codigo in codigos
    ]
    resultados = [
        {
            "ruleId": achado.codigo,
            "ruleIndex": indices[achado.codigo],
            "level": _NIVEL_SARIF[achado.severidade],
            "message": {
                "text": f"Possível segredo detectado: {achado.tipo}."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(achado.arquivo, safe="/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": max(achado.linha, 1)},
                    }
                }
            ],
            "properties": {
                "severidade": achado.severidade,
                "trechoOfuscado": achado.trecho_ofuscado,
                "ocorrencias": achado.ocorrencias,
                "arquivosAfetados": len(achado.arquivos_afetados) or 1,
                "primeiroCommit": achado.primeiro_commit or achado.commit,
                "commitMaisRecente": (
                    achado.commit_mais_recente or achado.commit
                ),
            },
        }
        for achado in achados
    ]
    documento = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "leak-hunt",
                        "semanticVersion": __version__,
                        "informationUri": (
                            "https://github.com/kaue34381210-star/leak-hunt"
                        ),
                        "rules": regras,
                    }
                },
                "results": resultados,
            }
        ],
    }
    return json.dumps(documento, ensure_ascii=False, indent=2)
