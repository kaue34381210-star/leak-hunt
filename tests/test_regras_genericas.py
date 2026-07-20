import pytest

from leak_hunt.regras import detectar


@pytest.mark.parametrize(
    ("texto", "codigo"),
    [
        ("chave = " + "AKIA" + "FAKE" + "0" * 12, "aws-access-key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private-key"),
        (
            "token = " + "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12,
            "jwt",
        ),
    ],
)
def test_detecta_segredos_genericos(texto: str, codigo: str) -> None:
    assert [achado.codigo for achado in detectar(texto)] == [codigo]


@pytest.mark.parametrize(
    "texto",
    [
        "chave = AKIA123",
        "-----BEGIN PUBLIC KEY-----",
        "eyJcurto.eyJcurto.assinatura",
        "código sem credenciais",
    ],
)
def test_ignora_texto_sem_segredo_generico(texto: str) -> None:
    assert list(detectar(texto)) == []
