import json
from pathlib import Path

from leak_hunt.regras import Deteccao
from leak_hunt.relatorio import (
    Achado,
    criar_achado,
    filtrar_por_limiar,
    formatar_json,
    formatar_texto,
    ofuscar,
)
from leak_hunt.varredura import LinhaAdicionada


def test_ofusca_valores_sem_expor_o_conteudo_completo() -> None:
    assert ofuscar("curto") == "*****"
    assert ofuscar("abcdefghijkl") == "abcd…ijkl"


def test_formata_metadados_e_trecho_ofuscado() -> None:
    segredo = "AKIA" + "FAKE" + "0" * 12
    linha = LinhaAdicionada(
        commit="a" * 40,
        autor="Pessoa de Teste",
        data="2026-07-20T10:00:00-03:00",
        arquivo="config.py",
        numero=8,
        conteudo=f'CHAVE = "{segredo}"',
    )
    deteccao = Deteccao(
        codigo="aws-access-key",
        tipo="AWS Access Key",
        valor=segredo,
        inicio=9,
        fim=29,
    )

    relatorio = formatar_texto([criar_achado(linha, deteccao)], 10)

    assert "AWS Access Key (aws-access-key)" in relatorio
    assert "config.py:8" in relatorio
    assert "Pessoa de Teste" in relatorio
    assert segredo not in relatorio
    assert "AKIA…0000" in relatorio


def test_filtra_achados_abaixo_do_limiar_no_mesmo_arquivo() -> None:
    def achado(arquivo: str) -> Achado:
        return Achado(
            codigo="cpf-hardcoded",
            tipo="CPF hardcoded em massa",
            commit="a" * 40,
            autor="Teste",
            data="2026-07-20T10:00:00-03:00",
            arquivo=arquivo,
            linha=1,
            trecho_ofuscado="529.…7-25",
            minimo_por_arquivo=5,
        )

    abaixo_do_limiar = [achado("a.py") for _ in range(4)]
    no_limiar = [achado("b.py") for _ in range(5)]

    assert filtrar_por_limiar(abaixo_do_limiar + no_limiar) == no_limiar


def test_formata_json_sem_expor_segredo() -> None:
    segredo = "AKIA" + "FAKE" + "0" * 12
    achado = Achado(
        codigo="aws-access-key",
        tipo="AWS Access Key",
        commit="a" * 40,
        autor="Teste",
        data="2026-07-20T10:00:00-03:00",
        arquivo="config.py",
        linha=3,
        trecho_ofuscado=ofuscar(segredo),
    )

    relatorio = formatar_json([achado], 12, Path("/tmp/repositorio"))
    documento = json.loads(relatorio)

    assert documento["versao_schema"] == 1
    assert documento["resumo"] == {
        "linhas_adicionadas_analisadas": 12,
        "total_achados": 1,
    }
    assert documento["achados"][0]["arquivo"] == "config.py"
    assert documento["achados"][0]["trecho_ofuscado"] == "AKIA…0000"
    assert segredo not in relatorio
