import pytest

from leak_hunt.regras import detectar


@pytest.mark.parametrize("arquivo", [".env", "config/.env.production"])
def test_detecta_valor_nao_vazio_em_env_real(arquivo: str) -> None:
    deteccoes = list(detectar("API_TOKEN=valor-falso", arquivo=arquivo))

    assert [item.codigo for item in deteccoes] == ["env-value"]
    assert deteccoes[0].valor == "valor-falso"


@pytest.mark.parametrize(
    ("linha", "arquivo"),
    [
        ("API_TOKEN=valor-falso", "config.py"),
        ("API_TOKEN=valor-falso", ".env.example"),
        ("API_TOKEN=", ".env"),
        ('API_TOKEN=""', ".env"),
        ('API_TOKEN="   "', ".env"),
        ("API_TOKEN=# vazio", ".env"),
        ("# API_TOKEN=valor-falso", ".env"),
    ],
)
def test_ignora_valor_fora_de_env_real_ou_vazio(linha: str, arquivo: str) -> None:
    assert not any(
        item.codigo == "env-value" for item in detectar(linha, arquivo=arquivo)
    )
