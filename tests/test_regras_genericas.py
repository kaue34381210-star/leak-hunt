import pytest

from leak_hunt.regras import ErroSelecaoRegras, detectar, selecionar_regras


@pytest.mark.parametrize(
    ("texto", "codigo", "severidade"),
    [
        (
            "chave = " + "AKIA" + "FAKE" + "0" * 12,
            "aws-access-key",
            "critico",
        ),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private-key", "critico"),
        (
            "token = " + "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12,
            "jwt",
            "alto",
        ),
    ],
)
def test_detecta_segredos_genericos(
    texto: str,
    codigo: str,
    severidade: str,
) -> None:
    deteccoes = list(detectar(texto))

    assert [achado.codigo for achado in deteccoes] == [codigo]
    assert [achado.severidade for achado in deteccoes] == [severidade]


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


@pytest.mark.parametrize("prefixo", ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"])
def test_detecta_tokens_de_acesso_github(prefixo: str) -> None:
    token = prefixo + "A" * 36

    assert [item.codigo for item in detectar(f'token = "{token}"')] == [
        "github-pat"
    ]
    assert next(detectar(token)).severidade == "critico"


def test_ignora_token_github_curto() -> None:
    assert list(detectar("token = " + "ghp_" + "A" * 12)) == []


@pytest.mark.parametrize(
    "valor",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAI44QH8DHBEXAMPLE",
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ),
    ],
)
def test_ignora_exemplos_publicos_exatos(valor: str) -> None:
    assert list(detectar(f'credencial = "{valor}"')) == []


def test_nao_permite_automaticamente_valor_parecido_com_exemplo() -> None:
    valor = "AKIAIOSFODNN7EXAMPLF"

    assert [item.codigo for item in detectar(valor)] == ["aws-access-key"]
