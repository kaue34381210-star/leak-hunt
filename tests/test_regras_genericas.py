import pytest

from leak_hunt.regras import ErroSelecaoRegras, detectar, selecionar_regras


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


def test_seleciona_e_ignora_regras_por_codigo() -> None:
    assert [regra.codigo for regra in selecionar_regras(somente=("jwt",))] == [
        "jwt"
    ]
    assert "jwt" not in {
        regra.codigo for regra in selecionar_regras(ignorar=("jwt",))
    }


def test_rejeita_codigo_de_regra_inexistente() -> None:
    with pytest.raises(ErroSelecaoRegras, match="inexistente"):
        selecionar_regras(somente=("inexistente",))


def test_detecta_jwt_terminado_em_hifen() -> None:
    token = "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 11 + "-"

    assert [item.codigo for item in detectar(f'token = "{token}"')] == ["jwt"]


def test_nao_detecta_jwt_embutido_em_base64url_maior() -> None:
    token = "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12

    assert list(detectar(f"prefixo_{token}_sufixo")) == []
