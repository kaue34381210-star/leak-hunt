import json
from pathlib import Path

from leak_hunt.baseline import criar_fingerprint
from leak_hunt.regras import Deteccao
from leak_hunt.relatorio import (
    Achado,
    AgregadorAchados,
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
        severidade="critico",
    )

    relatorio = formatar_texto([criar_achado(linha, deteccao)], 10)

    assert "AWS Access Key (aws-access-key)" in relatorio
    assert "Severidade: critico" in relatorio
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


def test_deduplica_segredo_e_agrega_origens() -> None:
    segredo = "AKIA" + "FAKE" + "0" * 12
    deteccao = Deteccao(
        codigo="aws-access-key",
        tipo="AWS Access Key",
        valor=segredo,
        inicio=0,
        fim=len(segredo),
    )
    antiga = LinhaAdicionada(
        commit="a" * 40,
        autor="Teste",
        data="2025-01-01T10:00:00+00:00",
        arquivo="a.py",
        numero=1,
        conteudo=segredo,
    )
    recente = LinhaAdicionada(
        commit="b" * 40,
        autor="Teste",
        data="2026-01-01T10:00:00+00:00",
        arquivo="b.py",
        numero=2,
        conteudo=segredo,
    )
    agregador = AgregadorAchados()

    agregador.adicionar(recente, deteccao)
    agregador.adicionar(antiga, deteccao)
    achados = agregador.finalizar()

    assert len(achados) == 1
    assert achados[0].ocorrencias == 2
    assert achados[0].arquivos_afetados == ("a.py", "b.py")
    assert achados[0].primeiro_commit == "a" * 40
    assert achados[0].commit_mais_recente == "b" * 40
    assert achados[0].severidade == "alto"


def test_nao_colide_segredos_com_mesmo_trecho_ofuscado() -> None:
    valores = ("AKIA" + "FAKE" + "0" * 12, "AKIA" + "TEST" + "0" * 12)
    linha = LinhaAdicionada(
        commit="a" * 40,
        autor="Teste",
        data="2026-01-01T10:00:00+00:00",
        arquivo="config.py",
        numero=1,
        conteudo="",
    )
    agregador = AgregadorAchados()
    for valor in valores:
        agregador.adicionar(
            linha,
            Deteccao(
                codigo="aws-access-key",
                tipo="AWS Access Key",
                valor=valor,
                inicio=0,
                fim=len(valor),
            ),
        )

    assert len(agregador.finalizar()) == 2


def test_agregador_respeita_limiar_por_arquivo() -> None:
    valor = "529.982." + "247-25"
    deteccao = Deteccao(
        codigo="cpf-hardcoded",
        tipo="CPF hardcoded em massa",
        valor=valor,
        inicio=0,
        fim=len(valor),
        minimo_por_arquivo=5,
    )
    linha = LinhaAdicionada(
        commit="a" * 40,
        autor="Teste",
        data="2026-01-01T10:00:00+00:00",
        arquivo="clientes.py",
        numero=1,
        conteudo=valor,
    )
    agregador = AgregadorAchados()

    for _ in range(4):
        agregador.adicionar(linha, deteccao)
    assert agregador.finalizar() == []

    agregador.adicionar(linha, deteccao)
    assert agregador.finalizar()[0].ocorrencias == 5


def test_agregador_ignora_fingerprint_da_baseline() -> None:
    segredo = "AKIA" + "BASE" + "0" * 12
    linha = LinhaAdicionada(
        commit="a" * 40,
        autor="Teste",
        data="2026-01-01T10:00:00+00:00",
        arquivo="config.py",
        numero=1,
        conteudo=segredo,
    )
    deteccao = Deteccao(
        codigo="aws-access-key",
        tipo="AWS Access Key",
        valor=segredo,
        inicio=0,
        fim=len(segredo),
    )
    fingerprint = criar_fingerprint(deteccao.codigo, segredo, linha.arquivo)
    agregador = AgregadorAchados(frozenset({fingerprint}))

    agregador.adicionar(linha, deteccao)

    assert agregador.finalizar() == []
    assert agregador.fingerprints() == set()


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
        severidade="critico",
    )

    relatorio = formatar_json([achado], 12, Path("/tmp/repositorio"))
    documento = json.loads(relatorio)

    assert documento["versao_schema"] == 1
    assert documento["resumo"] == {
        "linhas_adicionadas_analisadas": 12,
        "total_achados": 1,
        "total_ocorrencias": 1,
    }
    assert documento["achados"][0]["arquivo"] == "config.py"
    assert documento["achados"][0]["severidade"] == "critico"
    assert documento["achados"][0]["trecho_ofuscado"] == "AKIA…0000"
    assert segredo not in relatorio
