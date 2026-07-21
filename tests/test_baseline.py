import json

import pytest

from leak_hunt.baseline import (
    ARQUIVO_BASELINE,
    ErroBaseline,
    carregar_baseline,
    criar_fingerprint,
    salvar_baseline,
)


def test_salva_e_carrega_fingerprints_sem_valor_bruto(tmp_path) -> None:
    segredo = "segredo-que-nao-pode-ser-persistido"
    fingerprint = criar_fingerprint("regra", segredo, "config.py")

    caminho = salvar_baseline(tmp_path, {fingerprint})

    conteudo = caminho.read_text(encoding="utf-8")
    documento = json.loads(conteudo)
    assert segredo not in conteudo
    assert documento["versao_schema"] == 1
    assert documento["algoritmo"] == "sha256"
    assert carregar_baseline(tmp_path) == frozenset({fingerprint})


def test_fingerprint_muda_com_regra_valor_ou_caminho() -> None:
    original = criar_fingerprint("regra", "valor", "a.py")

    assert criar_fingerprint("outra", "valor", "a.py") != original
    assert criar_fingerprint("regra", "outro", "a.py") != original
    assert criar_fingerprint("regra", "valor", "b.py") != original


def test_rejeita_baseline_malformada(tmp_path) -> None:
    (tmp_path / ARQUIVO_BASELINE).write_text(
        '{"versao_schema": 1, "fingerprints": ["invalido"]}',
        encoding="utf-8",
    )

    with pytest.raises(ErroBaseline, match="fingerprints inválida"):
        carregar_baseline(tmp_path)
