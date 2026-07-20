"""Modelos e formatação dos resultados da varredura."""

from dataclasses import dataclass

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
    )


def formatar_texto(achados: list[Achado], total_linhas: int) -> str:
    """Formata um relatório legível sem expor os segredos encontrados."""
    if not achados:
        return (
            "Nenhum segredo encontrado.\n"
            f"Linhas adicionadas analisadas: {total_linhas}"
        )

    partes = [
        f"Possíveis segredos encontrados: {len(achados)}",
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
                f"    Trecho: {achado.trecho_ofuscado}",
            ]
        )
    return "\n".join(partes)
