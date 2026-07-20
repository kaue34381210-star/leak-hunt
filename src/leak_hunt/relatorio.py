"""Modelos e formatação dos resultados da varredura."""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path

from leak_hunt.regras import Deteccao
from leak_hunt.varredura import LinhaAdicionada


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


@dataclass(slots=True)
class _GrupoAchados:
    codigo: str
    tipo: str
    trecho_ofuscado: str
    minimo_por_arquivo: int
    ocorrencias: int
    por_arquivo: Counter[str]
    primeira_linha: LinhaAdicionada
    linha_mais_recente: LinhaAdicionada


class AgregadorAchados:
    """Deduplica ocorrências sem manter o valor bruto ou cada ocorrência."""

    def __init__(self) -> None:
        self._grupos: dict[tuple[str, bytes], _GrupoAchados] = {}

    def adicionar(self, linha: LinhaAdicionada, deteccao: Deteccao) -> None:
        """Acrescenta uma ocorrência ao grupo do mesmo segredo e regra."""
        resumo = hashlib.sha256(
            deteccao.valor.encode("utf-8", errors="surrogatepass")
        ).digest()
        chave = (deteccao.codigo, resumo)
        grupo = self._grupos.get(chave)
        if grupo is None:
            self._grupos[chave] = _GrupoAchados(
                codigo=deteccao.codigo,
                tipo=deteccao.tipo,
                trecho_ofuscado=ofuscar(deteccao.valor),
                minimo_por_arquivo=deteccao.minimo_por_arquivo,
                ocorrencias=1,
                por_arquivo=Counter({linha.arquivo: 1}),
                primeira_linha=linha,
                linha_mais_recente=linha,
            )
            return

        grupo.ocorrencias += 1
        grupo.por_arquivo[linha.arquivo] += 1
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
